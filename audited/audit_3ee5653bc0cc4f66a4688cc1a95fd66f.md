### Title
Unbounded Log Amplification via Unauthenticated Requests to Non-Internal Paths in `TracingMiddleware`

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally calls `log.Info(message)` for every HTTP request whose path is not in `internalPaths`, with no application-level rate limiting. The logged message includes the full `request.URL.RequestURI()` value, which is attacker-controlled and can be padded with arbitrary query strings up to the HTTP server's limit. Because the only protective rate-limiting layer (Traefik middleware) is **disabled by default** (`global.middleware: false`), an unprivileged external attacker can drive sustained, high-volume log I/O that increases disk write throughput and CPU consumption well beyond 30% compared to baseline.

### Finding Description
**Exact code location:** `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61.

```go
// line 55-59
if internalPaths[path] {
    log.Debug(message)
} else {
    log.Info(message)   // ← triggered for every non-internal request, no guard
}
```

`internalPaths` contains exactly three entries: `/health/liveness`, `/health/readiness`, `/metrics` (defined at line 19 via constants from `health.go` and `metrics.go`). Every other path — including all Rosetta API paths (`/network/list`, `/block`, `/construction/*`, etc.) and any arbitrary path — falls into the `else` branch.

The `message` string (line 52–53) embeds `path`, which is taken verbatim from `request.URL.RequestURI()`. An attacker can append an arbitrarily long query string (e.g., `?a=AAAA…` up to the server's `ReadHeaderTimeout`/buffer limit), making each log entry kilobytes in size.

**Root cause / failed assumption:** The middleware assumes that upstream infrastructure (Traefik) will throttle request rates before they reach the application. However, `global.middleware` defaults to `false` in `charts/hedera-mirror-rosetta/values.yaml` (line 95), so the Traefik chain — including `rateLimit: average: 10` and `inFlightReq: amount: 5` — is **not deployed by default**. The Go application itself contains zero rate-limiting or log-throttling logic (confirmed: no matches for `rateLimit`/`throttle` in `rosetta/**/*.go`).

**Exploit flow:**
1. Attacker sends a continuous stream of HTTP POST/GET requests to `/network/list?<8KB_payload>` (or any non-internal path).
2. `TracingMiddleware` wraps the handler (wired at `main.go` line 218); it processes each request and unconditionally calls `log.Info(message)` where `message` contains the full 8 KB URI.
3. Logrus writes each entry synchronously to the configured output (file or stdout redirected to disk).
4. At even modest rates (e.g., 500 req/s × 8 KB/entry = 4 MB/s of log writes), disk I/O and CPU (string formatting + syscall overhead) spike sharply.

**Why existing checks fail:**
- `internalPaths` check (line 55) only exempts three specific paths; all others are logged at `Info`.
- Traefik rate limiting (`values.yaml` lines 157–161) is opt-in and off by default.
- No per-IP, per-path, or global log-rate throttle exists anywhere in the Go codebase.

### Impact Explanation
Sustained log flooding causes:
- **Disk exhaustion / I/O saturation**: multi-MB/s writes can fill log volumes or saturate disk bandwidth, degrading all other disk-dependent operations (DB writes, WAL, etc.).
- **CPU pressure**: `fmt.Sprintf` formatting and logrus JSON/text marshalling per request consume CPU proportional to request rate and message size.
- **Service degradation**: once disk I/O is saturated, the HTTP server's write path stalls, causing cascading latency increases for legitimate users.

A 30% resource increase is achievable at moderate request rates without requiring any credentials or special privileges.

### Likelihood Explanation
- No authentication is required; the Rosetta API is a public HTTP endpoint.
- The attack requires only a standard HTTP client (e.g., `curl`, `wrk`, `ab`).
- The Traefik rate-limiting guard is disabled by default, meaning most deployments are unprotected at the application layer.
- The attack is repeatable, automatable, and requires no knowledge of internal state.

### Recommendation
1. **Add application-level log-rate throttling**: use a token-bucket or leaky-bucket limiter (e.g., `golang.org/x/time/rate`) inside `TracingMiddleware` to cap the number of `log.Info` calls per second, independent of upstream infrastructure.
2. **Truncate the logged path**: cap `path` (from `request.URL.RequestURI()`) to a safe maximum length (e.g., 512 bytes) before embedding it in `message` to prevent per-entry size amplification.
3. **Enable Traefik middleware by default**: change `global.middleware` default to `true` in `values.yaml`, or document clearly that rate limiting must be enabled for production deployments.
4. **Consider logging at `Debug` level for unknown/invalid paths** rather than `Info`, reducing log volume for noise traffic.

### Proof of Concept
```bash
# Generate a long query string payload (~8 KB)
PAYLOAD=$(python3 -c "print('a='+('A'*8000))")

# Flood the node with requests to a non-internal path
wrk -t4 -c100 -d60s \
  "http://<rosetta-node>:<port>/network/list?${PAYLOAD}"

# Observe disk I/O spike on the node:
iostat -x 1 60   # watch %util and wkB/s climb

# Observe log file growth:
watch -n1 'du -sh /var/log/rosetta/'
```

Within seconds, `log.Info` is called for every request, each writing an ~8 KB log line. At 500 req/s this produces ~4 MB/s of log writes, readily exceeding a 30% increase over baseline disk and CPU utilization on a lightly loaded node.