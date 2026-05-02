### Title
Unbounded Attacker-Controlled Data Written to Log in `TracingMiddleware` Enables Disk Exhaustion DoS

### Summary
`TracingMiddleware()` in `rosetta/app/middleware/trace.go` unconditionally writes attacker-controlled request data — specifically the full `X-Forwarded-For`/`X-Real-IP` header value and the full request URI — into log entries at `Info` level for every non-internal path, with no length cap or sanitization. Because the application-level Traefik rate-limiting middleware is disabled by default (`global.middleware: false`), an unauthenticated remote attacker can flood the server with requests carrying large headers, rapidly filling the node's disk and crashing the process.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61:

```go
clientIpAddress := getClientIpAddress(request)   // line 46 — reads X-Real-IP or X-Forwarded-For verbatim
path := request.URL.RequestURI()                  // line 47 — full URI, attacker-controlled

message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)   // lines 52-53 — no truncation

if internalPaths[path] {
    log.Debug(message)
} else {
    log.Info(message)                             // line 58 — written for every non-internal path
}
```

`getClientIpAddress()` (lines 63–75) reads `X-Real-IP` then `X-Forwarded-For` with no length check:

```go
ipAddress := r.Header.Get(xRealIpHeader)
if len(ipAddress) == 0 {
    ipAddress = r.Header.Get(xForwardedForHeader)
}
```

**Root cause:** Both `clientIpAddress` and `path` are fully attacker-controlled strings that are concatenated into `message` and written to the log file without any truncation, sanitization, or rate-gate. The only branch (`internalPaths[path]`) merely selects between `log.Debug` and `log.Info`; it does not suppress logging.

**Why existing checks are insufficient:**

1. The `internalPaths` guard (line 55) only changes log verbosity — it does not prevent writing attacker data to disk.
2. Go's `net/http` default `MaxHeaderBytes` is 1 MB (1 << 20). No override is set in `rosetta/main.go` lines 220–227, so each request can carry up to ~1 MB in headers.
3. The Traefik rate-limiting middleware is gated on `global.middleware: false` (default, `charts/hedera-mirror-rosetta/values.yaml` line 95), meaning it is **off by default**. No application-level rate limiting exists in the Go server itself.

### Impact Explanation

An attacker who can reach the Rosetta API port (default 5700) can write up to ~1 MB of arbitrary data to the log per HTTP request. With no application-level rate limiting, a single attacker with modest bandwidth can exhaust the node's disk partition in minutes. Once the disk is full, the Go process cannot write logs, the database cannot write WAL/data files (if co-located), and the OS may kill processes — resulting in a complete node outage. This directly disrupts the Rosetta API service, which is used by exchanges and wallets to interact with the Hedera network.

### Likelihood Explanation

The attack requires no authentication, no special protocol knowledge, and no prior access. Any internet-reachable Rosetta node running with default Helm values (`global.middleware: false`) is vulnerable. The exploit is trivially scriptable with standard tools (`curl`, `ab`, `wrk`) and is fully repeatable. The attacker does not need to maintain a connection — fire-and-forget HTTP requests suffice.

### Recommendation

1. **Truncate logged fields**: Cap `clientIpAddress` and `path` to a safe maximum (e.g., 256 bytes) before including them in `message`.
2. **Enable rate limiting by default**: Change `global.middleware` default to `true` in `charts/hedera-mirror-rosetta/values.yaml`, or add application-level rate limiting inside `TracingMiddleware`.
3. **Set `MaxHeaderBytes`**: Explicitly set `http.Server.MaxHeaderBytes` to a small value (e.g., 8 KB) in `rosetta/main.go`.
4. **Sanitize for log injection**: Strip or escape newline characters (`\n`, `\r`) from all user-supplied values before logging to prevent log forging.

### Proof of Concept

```bash
# Generate ~900 KB of padding
PADDING=$(python3 -c "print('A' * 900000)")

# Flood the node — each request writes ~900 KB to the log
while true; do
  curl -s -o /dev/null \
    -H "X-Forwarded-For: ${PADDING}" \
    -X POST http://<rosetta-node>:5700/network/list \
    -H "Content-Type: application/json" \
    -d '{"metadata":{}}' &
done
```

Each iteration writes one `Info`-level log line containing ~900 KB of attacker data. With no rate limiting active (default config), disk exhaustion occurs proportional to available bandwidth. Once the disk partition fills, the node process crashes or becomes unresponsive.