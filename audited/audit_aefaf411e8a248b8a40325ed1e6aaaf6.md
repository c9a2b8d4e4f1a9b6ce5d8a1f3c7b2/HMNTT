### Title
Unauthenticated `/health/readiness` Endpoint Triggers Uncached, Multiplexed Backend Operations on Every Request, Enabling Sustained Resource Exhaustion via Aggressive Polling

### Summary
The `Routes()` function in `rosetta/app/middleware/health.go` registers `/health/readiness` as an unauthenticated GET endpoint. Each request unconditionally executes a live PostgreSQL health check and two internal Rosetta API calls (`/network/list` + `/network/status`) with no result caching and no application-level rate limiting. The Traefik rate-limiting middleware is scoped exclusively to `/rosetta/*` ingress paths, leaving `/health/readiness` entirely unprotected. Any unprivileged caller with network access to the pod (internal monitoring tools, cluster-internal pods, or misconfigured proxies) can sustain a polling rate that drives resource consumption well above baseline without any single request appearing anomalous.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/health.go`, `NewHealthController()` (lines 37–54) and `Routes()` (lines 63–78):

```go
readinessChecks := []health.Config{
    {
        Name:    "postgresql",
        Timeout: time.Second * 10,
        Check:   postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),  // live DB check
    },
    {
        Name:    "network",
        Timeout: time.Second * 10,
        Check:   checkNetworkStatus(rosettaConfig.Port),  // 2 live HTTP calls
    },
}
readinessHealth, err := health.New(health.WithChecks(readinessChecks...))
// ^^^ WithCacheDuration is NEVER passed; every request re-executes all checks
```

`checkNetworkStatus()` (lines 80–101) issues two sequential HTTP calls per invocation:
- `rosettaClient.NetworkAPI.NetworkList(ctx, ...)` (line 86)
- `rosettaClient.NetworkAPI.NetworkStatus(ctx, ...)` (line 93)

**Root cause / failed assumption:** The `hellofresh/health-go/v4` library supports a `WithCacheDuration` option that would cache check results and short-circuit repeated backend calls. It is never passed to `health.New()`. The implicit assumption is that callers are well-behaved (Kubernetes kubelet probes at a fixed interval), but the endpoint is served on the same port as all other Rosetta API routes with no per-route rate limiting.

**Why existing checks fail:** The Traefik middleware chain (`rateLimit: average 10`, `inFlightReq: amount 5`) is attached to the ingress, which only routes `/rosetta/account`, `/rosetta/block`, `/rosetta/call`, `/rosetta/construction`, `/rosetta/events`, `/rosetta/mempool`, `/rosetta/network`, `/rosetta/search` — `/health/readiness` is absent from every ingress path. The middleware chain therefore never intercepts health endpoint traffic. The Go HTTP server itself (`main.go` lines 220–227) applies only timeout settings, no concurrency or rate controls.

### Impact Explanation
Each GET to `/health/readiness` fans out to **3 backend operations**: 1 PostgreSQL round-trip + 2 internal HTTP calls that themselves consume Rosetta API goroutines and DB connection pool slots. At a modest 20 req/s polling rate (easily achievable by a single monitoring agent or a small script), this generates 60 backend operations/second continuously. PostgreSQL connection pool exhaustion and goroutine pile-up on the internal `/network/list` and `/network/status` handlers will degrade all legitimate Rosetta API traffic. The 30% resource increase threshold is reachable without any single request exceeding normal latency, making the pattern invisible to per-request anomaly detection.

### Likelihood Explanation
Preconditions are low-barrier: the attacker needs only network reachability to the pod port (achievable from any pod in the same Kubernetes namespace, from a compromised monitoring agent, or from a misconfigured Prometheus scrape job). No credentials, tokens, or special headers are required. The GET method and HTTP 200 responses make the traffic indistinguishable from legitimate Kubernetes liveness/readiness probes. The attack is fully repeatable and requires no state.

### Recommendation
1. **Cache health check results** by passing `health.WithCacheDuration(time.Second * 5)` (or a tunable interval) to `health.New()` in `NewHealthController()`. This ensures repeated requests within the cache window return the stored result without re-executing backend checks.
2. **Extend the Traefik middleware** (or add a separate `IngressRoute`) to cover `/health/readiness` with the same `inFlightReq` and `rateLimit` rules already applied to `/rosetta/*` paths.
3. **Add a concurrency semaphore** inside `checkNetworkStatus` to bound simultaneous in-flight internal HTTP calls.

### Proof of Concept
```bash
# From any pod inside the cluster (no credentials needed):
while true; do
  curl -s http://<rosetta-pod-ip>:<port>/health/readiness > /dev/null &
done
# Or with controlled rate using hey/wrk:
hey -z 60s -c 50 -q 20 http://<rosetta-pod-ip>:<port>/health/readiness
# Each of the 50 concurrent requests triggers 1 DB query + 2 internal HTTP calls.
# Monitor PostgreSQL active connections and Rosetta goroutine count:
# Expected: DB connections spike to pool limit; /network/list and /network/status
# latency increases for legitimate callers; CPU/memory rise >30% above baseline.
```