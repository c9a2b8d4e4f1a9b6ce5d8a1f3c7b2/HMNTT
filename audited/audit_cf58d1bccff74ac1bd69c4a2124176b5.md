### Title
Unbounded `log.Errorf` on Every Failed Readiness Check Enables Log-Flooding DoS via Unauthenticated `GET /health/readiness`

### Summary
The `checkNetworkStatus` function in `rosetta/app/middleware/health.go` calls `log.Errorf` unconditionally on every failed network or PostgreSQL check, with no rate limiting on either the HTTP endpoint or the log calls themselves. Because `GET /health/readiness` is publicly accessible with no authentication or request throttling, an unprivileged attacker can flood the endpoint at arbitrary speed, generating an unbounded stream of error log entries that exhaust available disk space (or I/O bandwidth) in any deployment where stdout is persisted to disk.

### Finding Description
**Exact code path:**

- `rosetta/app/middleware/health.go`, `checkNetworkStatus()`, lines 88 and 95:
  ```go
  log.Errorf("Readiness check, /network/list failed: %v", err)   // line 88
  log.Errorf("Readiness check, /network/status failed: %v", err) // line 95
  ```
- `rosetta/main.go`, line 54: `log.SetOutput(os.Stdout)` — all log output goes to stdout with no rotation or size cap configured in the application.
- `rosetta/main.go`, lines 217–219: the router is wrapped only in `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — none of which implement rate limiting.
- `rosetta/app/middleware/trace.go`, lines 55–58: health paths are logged at `Debug` level by the tracing middleware, but the `log.Errorf` calls inside the check function fire at `Error` level regardless of the configured log level.

**Root cause:** The `hellofresh/health-go` library executes the registered check functions synchronously on every HTTP request. When either the PostgreSQL or network check fails, `log.Errorf` is called once or twice per request with no guard, deduplication, or back-off. There is no per-IP rate limiter, no global request throttle, and no application-level log rate limiter anywhere in the rosetta middleware stack.

**Failed assumption:** The design assumes `/health/readiness` is called only by a Kubernetes kubelet or a controlled orchestrator at a low, fixed cadence. Nothing in the code enforces this assumption.

**Exploit flow:**
1. Attacker identifies the public `GET /health/readiness` endpoint (standard Rosetta/Kubernetes path, no auth).
2. Attacker arranges or waits for a condition where the PostgreSQL DSN is unreachable or the internal network check returns an error (e.g., during startup, a DB outage, or by exhausting DB connections from another vector).
3. Attacker sends requests in a tight loop (e.g., `while true; do curl -s http://<host>:<port>/health/readiness & done`).
4. Each request triggers `log.Errorf` at lines 88 and/or 95; because the network check connects to `localhost` and gets an immediate connection-refused when the service is down, the 10-second timeout is never reached and failures are near-instantaneous.
5. Log entries accumulate in stdout, which is captured by the container runtime (Docker json-file driver, containerd, etc.) and written to the node's disk. Without application-level or runtime-level log rotation, the disk fills.

### Impact Explanation
In Docker deployments using the default `json-file` log driver without `--log-opt max-size`, or in any environment where stdout is redirected to a file, disk exhaustion terminates the process or degrades I/O for the entire host. Even with log rotation configured at the runtime level, a sustained flood causes continuous high-rate disk writes that degrade I/O performance for co-located workloads. Because the Rosetta node is part of the Hedera/Hiero mirror infrastructure (a high-market-cap network), availability disruption has direct protocol-level consequences.

### Likelihood Explanation
The endpoint requires zero credentials. The attacker needs only network access to the Rosetta port (default 8082). The failure condition (DB or network down) can coincide with natural outages or be induced by a separate low-effort resource exhaustion. The attack is trivially scriptable with `curl` or `ab` and is fully repeatable. No exploit tooling beyond standard HTTP clients is required.

### Recommendation
1. **Add a per-endpoint rate limiter** (e.g., `golang.org/x/time/rate` token bucket) in a new middleware that wraps the health handler, rejecting requests above a threshold (e.g., 10 req/s) with HTTP 429.
2. **Deduplicate or suppress repeated log entries**: use a sampled/rate-limited logger (e.g., `logrus`'s hook pattern or a `sync.Once`-style suppressor) so that the same error is not emitted more than once per N seconds.
3. **Cache health check results** for a short TTL (e.g., 5 seconds) so that a flood of HTTP requests does not translate into a flood of check executions and log writes.
4. **Configure container-runtime log rotation** (`--log-opt max-size=50m --log-opt max-file=3`) as a deployment-level defence-in-depth measure, and document this as a required hardening step.

### Proof of Concept
```bash
# Precondition: PostgreSQL or the Rosetta network service is down/unreachable
# (naturally occurs during startup or DB maintenance)

# Step 1: confirm the endpoint is unauthenticated
curl -v http://<rosetta-host>:8082/health/readiness
# Expected: HTTP 503 {"status":"UNAVAILABLE",...}

# Step 2: flood the endpoint
for i in $(seq 1 10000); do
  curl -s http://<rosetta-host>:8082/health/readiness > /dev/null &
done
wait

# Step 3: observe log volume on the host
# Docker:
sudo du -sh /var/lib/docker/containers/<container-id>/*.log

# Step 4: confirm disk exhaustion or I/O saturation
df -h /var/lib/docker
iostat -x 1 5
```
Each iteration produces one or two `log.Errorf` lines (lines 88/95 of `health.go`). At 1 000 req/s with a 200-byte log line per request, this generates ~200 KB/s of log data — enough to exhaust a typical container log partition within minutes if rotation is absent.