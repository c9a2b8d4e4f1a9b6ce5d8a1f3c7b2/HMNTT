### Title
Unprivileged External Access to `/health/readiness` Suppressed from Production Audit Logs via `internalPaths` Debug-Level Routing

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` deliberately routes log output for `/health/readiness` (and other `internalPaths`) to `log.Debug` instead of `log.Info`. In any production deployment where the log level is set to INFO or higher (the standard), all external accesses to this endpoint are silently dropped from exported records. An unprivileged external user can repeatedly probe the endpoint, receive valid responses, and leave no trace in the audit log.

### Finding Description
In `rosetta/app/middleware/trace.go`, line 19 defines:

```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

`readinessPath` is `/health/readiness` (defined in `health.go` line 21). Inside `TracingMiddleware` (lines 55–59):

```go
if internalPaths[path] {
    log.Debug(message)
} else {
    log.Info(message)
}
```

The path check is a simple exact-match map lookup on `request.URL.RequestURI()`. When the path matches, the entire access record — including client IP, method, status code, and latency — is emitted only at `Debug` level. In production, where the effective log level is `INFO`, this message is discarded before it reaches any log exporter or audit sink. The endpoint itself is publicly routable (no authentication is enforced), so any external client can reach it. There is no secondary audit mechanism, no rate-limit log, and no separate access record written for these paths.

Additionally, the readiness handler internally calls `checkNetworkStatus` (`health.go` lines 80–100), which makes outbound HTTP calls to `/network/list` and `/network/status` on `localhost`. Those internal calls pass through `TracingMiddleware` themselves and are logged at `Info` level — but they are attributed to `127.0.0.1`, not to the original external caller, so the external actor's identity is still absent from the audit trail.

### Impact Explanation
Any external actor can send arbitrary volumes of `GET /health/readiness` requests and receive accurate service-readiness signals (HTTP 200 vs. 503, including implicit confirmation that PostgreSQL and the Rosetta network layer are reachable) without a single record appearing in production-level logs or any downstream log-aggregation or SIEM system. This constitutes a complete audit-trail gap for an externally-accessible, unauthenticated endpoint. In environments where access logs feed security monitoring or compliance reporting, this gap means the endpoint is effectively a blind spot: reconnaissance, availability probing, and timing-based side-channel analysis can all proceed undetected.

### Likelihood Explanation
No privileges, credentials, or special network position are required. Any internet-reachable deployment is trivially exploitable with a single `curl` command. The behavior is deterministic and 100% reproducible as long as the production log level is INFO (the default configured in `rosetta/main.go`). The attacker needs no knowledge of the codebase — probing health endpoints is standard reconnaissance practice.

### Recommendation
Remove `readinessPath` (and `livenessPath`) from `internalPaths`, or replace the blanket debug suppression with a sampling/rate-limited Info log (e.g., log every Nth request or only on non-200 responses). If noise reduction is the goal, use a structured log filter at the exporter layer rather than suppressing at the source. At minimum, ensure a separate, append-only access log captures all HTTP requests regardless of log level, so the audit trail is complete even when debug output is disabled.

### Proof of Concept
```
# Against a production Rosetta instance (log level = INFO):
for i in $(seq 1 100); do
  curl -s -o /dev/null -w "%{http_code}\n" http://<rosetta-host>/health/readiness
done

# Expected: 100x "200" responses returned to the caller.
# Observed in production logs: zero entries for /health/readiness.
# The 100 accesses, client IP, and response codes are entirely absent
# from any log file, log aggregator, or SIEM alert.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L19-19)
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

**File:** rosetta/app/middleware/trace.go (L55-59)
```go
		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
```

**File:** rosetta/app/middleware/health.go (L20-22)
```go
	livenessPath  = "/health/liveness"
	readinessPath = "/health/readiness"
)
```
