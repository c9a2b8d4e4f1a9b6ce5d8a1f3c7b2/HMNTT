### Title
Unbounded Concurrent Health Check Requests Enable Resource Exhaustion via Recursive HTTP Amplification on `/health/readiness`

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` has no application-level concurrency limit. Each request spawns goroutines that make two outbound HTTP calls back to the same server (`/network/list` and `/network/status`) with a 10-second timeout, creating a recursive amplification loop. The Traefik `inFlightReq` and `rateLimit` middleware protections are scoped exclusively to `/rosetta/*` ingress paths and do not cover the health endpoint, leaving it fully unprotected against flood attacks from unprivileged external users in direct-exposure deployments.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/health.go`, `NewHealthController` (lines 37–50) registers two readiness checks, each with `Timeout: time.Second * 10`. The `checkNetworkStatus` closure (lines 80–101) makes two sequential HTTP calls to `localhost:<port>/network/list` and `localhost:<port>/network/status` — back into the same server process.

```go
// health.go lines 37-50
readinessChecks := []health.Config{
    {Name: "postgresql", Timeout: time.Second * 10, ...},
    {Name: "network",    Timeout: time.Second * 10, Check: checkNetworkStatus(rosettaConfig.Port)},
}
```

```go
// health.go lines 85-97
return func(ctx context.Context) (checkErr error) {
    networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, &types.MetadataRequest{})
    ...
    _, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, &types.NetworkRequest{...})
    ...
}
```

**Root cause:** Go's `net/http` server handles every incoming request in a new goroutine. The `hellofresh/health-go` `HandlerFunc` runs each registered check in its own goroutine. There is no semaphore, `sync.WaitGroup` cap, or channel-based concurrency gate anywhere in the health handler or the middleware chain (`MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware` → Router in `rosetta/main.go` lines 217–219).

**Why existing checks fail:**

The Traefik middleware (`inFlightReq: amount: 5`, `rateLimit: average: 10`) is defined in `charts/hedera-mirror-rosetta/values.yaml` lines 152–160, but the ingress only routes `/rosetta/account`, `/rosetta/block`, `/rosetta/call`, `/rosetta/construction`, `/rosetta/events`, `/rosetta/mempool`, `/rosetta/network`, `/rosetta/search` (lines 126–133). `/health/readiness` is absent from the ingress path list entirely, so Traefik never sees those requests. Additionally, the middleware block is gated on `{{ if and .Values.global.middleware .Values.middleware }}` and `middleware: false` is the default at line 95, meaning the protection is opt-in and off by default.

In the direct Docker deployment (the documented production-equivalent path: `docker run -p 5700:5700 ...`), port 5700 is exposed directly with zero intermediary protection.

### Impact Explanation
Each flood request to `/health/readiness`:
1. Spawns goroutines in the `health-go` handler (one per check).
2. The `checkNetworkStatus` goroutine opens two new HTTP client connections back to `localhost:5700`, each buffering request/response data and holding a 10-second context.
3. Those inbound `/network/list` and `/network/status` requests hit the database, consuming connections from the pool (default `maxOpenConnections: 100`).

With N concurrent flood requests: N×2 loopback HTTP connections are held open for up to 10 seconds, N×2 database queries are in flight, and goroutine/file-descriptor counts grow linearly. At scale (thousands of requests), this exhausts the DB connection pool (causing legitimate requests to queue/fail), saturates file descriptors, and accumulates memory from HTTP buffers (~64 KB–1 MB per connection pair), making OOM plausible on memory-constrained nodes. The recursive self-call means each attacker request generates at least 2 additional server-side requests, amplifying CPU and I/O load by a factor of ≥3.

Severity: **Medium** — consistent with the stated scope of ≥30% node shutdown without brute force, achievable by a single attacker with a modest flood tool.

### Likelihood Explanation
No authentication, no API key, no client certificate is required to call `/health/readiness`. In any deployment where port 5700 is directly reachable (Docker `-p 5700:5700`, bare-metal, or a misconfigured Kubernetes `NodePort`/`LoadBalancer` service), any unprivileged external user can execute this attack with a standard HTTP flood tool (`wrk`, `hey`, `ab`). The 10-second hold time means even a modest 100 req/s sustains 1,000 concurrent goroutines and 2,000 loopback connections at steady state. The attack is trivially repeatable and requires no exploit chain.

### Recommendation
1. **Application-level concurrency gate:** Add a buffered channel semaphore or `golang.org/x/sync/semaphore` in the health handler to cap concurrent readiness checks (e.g., 10–20).
2. **Decouple the network check from a loopback HTTP call:** Replace the self-referential HTTP call in `checkNetworkStatus` with a direct in-process service call, eliminating the recursive amplification.
3. **Expose health endpoints on a separate, non-public port** (e.g., a management port bound to `127.0.0.1` or a cluster-internal interface only), consistent with Kubernetes best practice for probe endpoints.
4. **Add `/health/readiness` to the Traefik ingress middleware chain** if it must remain on the public port, and enable `inFlightReq` protection for it.
5. **Enable the Traefik middleware by default** (`middleware: true`) rather than leaving it opt-in.

### Proof of Concept
```bash
# Precondition: rosetta node running with port 5700 directly reachable
# Tool: wrk (https://github.com/wrafael/wrk)

wrk -t 50 -c 5000 -d 30s http://<target>:5700/health/readiness

# Expected result:
# - /network/list and /network/status requests flood the server from within
# - DB connection pool (max 100) exhausted within seconds
# - Goroutine count climbs to 10,000+
# - Memory grows from loopback HTTP buffers
# - Legitimate API requests begin timing out or returning 500
# - Node becomes unresponsive; Kubernetes readiness probe fails -> pod marked NotReady
# - If ≥30% of rosetta pods are targeted simultaneously, network processing capacity
#   drops below the 30% threshold defined in the scope
```