### Title
Log-Level Bypass via Query String in `TracingMiddleware` Enables Info-Log Flooding

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` uses `request.URL.RequestURI()` to obtain the request path, which includes the raw query string. The `internalPaths` map is keyed on bare paths (e.g., `/health/liveness`) with no query string, so any request to `/health/liveness?x=anything` fails the map lookup and is logged at `log.Info` instead of `log.Debug`. An unauthenticated attacker can exploit this to flood the info-level log with health-check noise, burying legitimate transaction-related entries and making chronological reconstruction of transaction history impractical.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61:

```go
path := request.URL.RequestURI()          // line 47 — includes "?x=random"
...
if internalPaths[path] {                  // line 55 — map key is "/health/liveness"
    log.Debug(message)                    //   never reached for "?"-suffixed paths
} else {
    log.Info(message)                     // line 58 — attacker lands here
}
```

`internalPaths` is declared at line 19:
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```
where `livenessPath = "/health/liveness"` (no query string).

**Root cause:** `net/http`'s `(*URL).RequestURI()` returns the full request URI including query string and fragment. The map lookup is an exact string comparison, so `/health/liveness?x=1` ≠ `/health/liveness` and the suppression guard is silently skipped.

**Failed assumption:** The developer assumed that health-check requests would never carry a query string, so an exact-string map lookup would be sufficient to identify internal paths.

**No rate limiting exists** anywhere in the Rosetta middleware chain (confirmed: no `rateLimit`, `throttle`, or `maxRequests` symbols in `rosetta/**/*.go`).

### Impact Explanation
The Rosetta info log is the primary audit trail for transaction-related API calls (e.g., `/block`, `/block/transaction`, `/construction/submit`). Flooding it with thousands of synthetic health-check entries at INFO level:
- Pushes legitimate transaction entries out of bounded log buffers or log-shipping windows.
- Makes it impossible to reconstruct the true chronological order of real transaction requests without expensive log deduplication.
- Can exhaust disk/storage allocated to logs, causing log rotation to drop older entries.

Severity: **Medium** (integrity of audit log; no direct fund theft, but directly undermines forensic capability).

### Likelihood Explanation
- **No authentication required** — `/health/liveness` is a public endpoint by design.
- **No rate limiting** — the middleware chain has no throttle.
- **Trivially scriptable** — a single `while true; do curl ...; done` loop suffices.
- **Bypasses the only guard** — the `internalPaths` check is the sole suppression mechanism and is defeated by a single `?` character.
- Any external actor with network access to the Rosetta port can execute this immediately.

### Recommendation
Replace `request.URL.RequestURI()` with `request.URL.Path` (which strips the query string) for the `internalPaths` lookup:

```go
// Before (vulnerable):
path := request.URL.RequestURI()

// After (fixed):
path     := request.URL.RequestURI()   // keep full URI for the log message
pathOnly := request.URL.Path           // use bare path for the map lookup

if internalPaths[pathOnly] {
    log.Debug(message)
} else {
    log.Info(message)
}
```

Additionally, consider adding a per-IP or global request-rate limit in the middleware chain for all endpoints.

### Proof of Concept
**Precondition:** Network access to the Rosetta service port (default 8082). No credentials needed.

**Trigger:**
```bash
# Flood the info log with health-check noise
for i in $(seq 1 10000); do
  curl -s "http://<rosetta-host>:8082/health/liveness?x=$RANDOM" &
done
wait
```

**Result:**
- Each request produces an INFO-level log line such as:
  `INFO 1.2.3.4 GET /health/liveness?x=17423 (200) in 1ms`
- Legitimate transaction log entries (e.g., from `/block/transaction`) are buried among thousands of health-check lines.
- Log-level filters set to INFO (the default production level) cannot distinguish these from real transaction events.
- Setting log level to WARN to escape the noise simultaneously suppresses all normal transaction audit entries.