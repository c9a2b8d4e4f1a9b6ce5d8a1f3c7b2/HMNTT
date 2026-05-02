### Title
Unauthenticated Log Flooding via Unbounded `/mempool` Endpoint in Rosetta Service

### Summary
The `Mempool()` function in `rosetta/app/services/mempool_service.go` immediately returns `ErrNotImplemented` for every request with no validation or early rejection. The `TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally emits a `log.Info` entry for every non-internal HTTP request, and the rosetta server stack contains zero rate-limiting middleware. Any unauthenticated external user can flood `/mempool` at arbitrary request rates, generating unbounded log volume that can exhaust log storage and thrash log rotation, obscuring legitimate operational signals.

### Finding Description
**Code path:**

- `rosetta/app/services/mempool_service.go`, `Mempool()`, lines 22–27: returns `nil, errors.ErrNotImplemented` unconditionally with no input validation, no early rejection, and no cost imposed on the caller.
- `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61: after every request completes, checks `if internalPaths[path]` (line 55). `/mempool` is not in `internalPaths` (which only contains `/liveness`, `/metrics`, `/readiness`), so the `else` branch at line 57–59 executes `log.Info(message)` unconditionally for every single request.
- `rosetta/main.go`, lines 217–219: the full middleware stack is `corsMiddleware → tracingMiddleware → metricsMiddleware → router`. A grep across all `rosetta/**/*.go` files for any rate-limiting or throttling construct returns **zero matches**. The web3 `ThrottleManagerImpl`/`ThrottleConfiguration` is entirely separate and does not apply to the rosetta service.

**Root cause:** `TracingMiddleware` has no sampling, no rate limiting, and no suppression logic. The failed assumption is that the rosetta service would be protected by an upstream reverse proxy or network-layer rate limiter; no such protection is enforced or documented in the codebase.

**Exploit flow:**
1. Attacker sends a continuous stream of POST requests to `POST /mempool` with a minimal valid JSON body (e.g., `{}`).
2. Each request reaches `Mempool()`, which returns immediately with `ErrNotImplemented` — zero server-side cost beyond the log write.
3. `TracingMiddleware` emits one `log.Info` line per request: `<ip> POST /mempool (500) in Xµs`.
4. Log volume grows linearly with request rate. At 10,000 req/s (trivially achievable from a single machine), this produces ~10,000 log lines/second.

**Why existing checks fail:** The `internalPaths` guard only suppresses logging for health/metrics endpoints. There is no per-IP connection limit, no request-rate cap, no log sampling, and no circuit breaker anywhere in the rosetta stack.

### Impact Explanation
Log storage can be exhausted, causing the logging subsystem to drop legitimate error entries or crash log rotation daemons. Operators lose visibility into real failures (e.g., database errors, authentication failures on other endpoints) because signal is buried in noise. On systems with synchronous log writes, sustained flooding can also introduce I/O back-pressure that degrades overall service latency. Severity is Medium: no funds are at risk, but operator visibility and incident response capability are materially degraded.

### Likelihood Explanation
No privileges, accounts, or special network position are required. A single attacker machine with a basic HTTP load tool (e.g., `wrk`, `hey`, `ab`) can sustain tens of thousands of requests per second. The endpoint is POST-accessible on the public rosetta port. The attack is trivially repeatable and requires no prior knowledge of the system beyond the standard Rosetta API specification, which documents `/mempool` as a standard endpoint.

### Recommendation
1. **Add rate-limiting middleware to the rosetta stack** (e.g., `golang.org/x/time/rate` token-bucket limiter) applied before `TracingMiddleware`, returning HTTP 429 when the per-IP or global rate is exceeded.
2. **Add log sampling in `TracingMiddleware`** for non-error responses: only log a configurable fraction (e.g., 1%) of 5xx responses from stub endpoints, similar to the `sampleRate` pattern used in `rest/middleware/responseHandler.js` (line 56).
3. **Return HTTP 501 Not Implemented** (rather than 500) from stub endpoints so operators can filter these from alerting rules without suppressing real errors.

### Proof of Concept
```bash
# Requires: wrk (https://github.com/wrapwrap/wrk) or equivalent
# Target: rosetta service default port 5700

cat > /tmp/mempool_body.lua <<'EOF'
wrk.method = "POST"
wrk.body   = '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'
wrk.headers["Content-Type"] = "application/json"
EOF

# Run for 30 seconds at 500 connections / 4 threads
wrk -t4 -c500 -d30s -s /tmp/mempool_body.lua http://<rosetta-host>:5700/mempool

# Observe: rosetta log file grows at ~hundreds of MB/minute
# tail -f /var/log/rosetta/rosetta.log | grep "/mempool" | pv -l > /dev/null
# Expected: thousands of "POST /mempool (500)" Info lines per second
# Legitimate error entries are buried / log rotation triggers continuously
```