### Title
Unauthenticated `/health/readiness` Endpoint Triggers Uncached Dual HTTP Round-Trips per Request, Enabling Sustained Resource Amplification

### Summary
`checkNetworkStatus()` in `rosetta/app/middleware/health.go` returns a closure that unconditionally performs two sequential HTTP calls to `/network/list` and `/network/status` on every invocation, with no result caching and no application-level rate limiting on the `/health/readiness` route. Because the health endpoint is served on the same port as the Rosetta API and is absent from the Traefik ingress path list, the Traefik rate-limiter never applies to it, leaving the endpoint fully unthrottled. An unprivileged caller who can reach the server port can flood `/health/readiness` and force a 3× internal request amplification (1 inbound → 2 loopback HTTP calls + 1 PostgreSQL query) per request, sustaining elevated CPU, goroutine, and DB connection consumption.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/health.go`, `checkNetworkStatus()`, lines 80–101:

```go
func checkNetworkStatus(port uint16) func(ctx context.Context) error {
    serverUrl := fmt.Sprintf("http://localhost:%d", port)
    cfg := client.NewConfiguration(serverUrl, "readiness-check", nil)
    rosettaClient := client.NewAPIClient(cfg)

    return func(ctx context.Context) (checkErr error) {
        networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, &types.MetadataRequest{})
        // ...
        _, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, &types.NetworkRequest{...})
        // ...
    }
}
```

Every call to the returned closure issues two fresh HTTP round-trips to the same server process. The `hellofresh/health-go/v4` library invokes all registered `Check` functions synchronously on every `HandlerFunc` call; it provides no built-in result caching or debouncing.

**Root cause:** The assumption that health probes arrive at a controlled, low rate (e.g., only from Kubernetes kubelet) is not enforced at the application layer. The failed assumption is that an external caller cannot reach `/health/readiness` at arbitrary frequency.

**Why existing checks fail:**

The middleware chain in `rosetta/main.go` (lines 217–219) is:
```
MetricsMiddleware → TracingMiddleware → CorsMiddleware
```
No rate-limiting middleware is present at the Go application level.

The Traefik middleware (`rateLimit: average: 10`, `inFlightReq: amount: 5`) is defined in `charts/hedera-mirror-rosetta/values.yaml` (lines 149–166), but it is attached only to the ingress, which routes exclusively:
```
/rosetta/account, /rosetta/block, /rosetta/call, /rosetta/construction,
/rosetta/events, /rosetta/mempool, /rosetta/network, /rosetta/search
```
`/health/readiness` is not in this list (lines 126–133). Traffic reaching the pod port directly — or in any non-Kubernetes deployment — bypasses Traefik entirely. The health endpoint is bound to the same `rosettaConfig.Port` as the API (`rosetta/main.go` line 221), so any network path that reaches the API port also reaches the health endpoint.

### Impact Explanation

Each inbound `GET /health/readiness` causes:
- 2 loopback HTTP connections + full request/response cycles to `/network/list` and `/network/status`
- 1 PostgreSQL query (the `postgresql` check runs in parallel)
- Goroutine allocation for each internal request handler

This is a 3× amplification of server-side work per external request. At modest flood rates (e.g., 100 req/s to `/health/readiness`), the server processes 200 additional internal HTTP requests per second plus 100 DB queries, all attributed to the health subsystem. This can sustain ≥30% elevated CPU and connection-pool consumption without any brute-force volume, because the amplification multiplies the cost of each individual request. Legitimate Rosetta API traffic degrades as goroutine and DB connection budgets are consumed.

### Likelihood Explanation

Preconditions are minimal: the attacker needs only TCP connectivity to the server's port (the same port used for the Rosetta API). In non-Kubernetes deployments this is trivially satisfied. In Kubernetes deployments, any pod in the cluster, any misconfigured NodePort/LoadBalancer, or any operator using `kubectl port-forward` exposes the endpoint. No credentials, tokens, or special headers are required. The attack is trivially repeatable with a single `curl` loop or any HTTP load tool.

### Recommendation

1. **Add a result cache inside the closure** with a short TTL (e.g., 5–10 seconds). Store the last check result and timestamp; return the cached result if the TTL has not elapsed. This eliminates the per-request HTTP amplification for all callers.

2. **Apply application-level rate limiting to `/health/readiness`** independently of the Traefik ingress, e.g., using `golang.org/x/time/rate` or a middleware that limits the health handler to N invocations per second.

3. **Move the health endpoint to a separate, non-public port** (management port pattern), so it is structurally inaccessible to external callers regardless of ingress configuration.

### Proof of Concept

```bash
# Precondition: network access to the Rosetta server port (e.g., 5700)
# No credentials required.

# Flood /health/readiness at 200 req/s using wrk
wrk -t4 -c50 -d60s http://<rosetta-host>:5700/health/readiness

# Each request causes the server to execute:
#   POST http://localhost:5700/network/list   (internal)
#   POST http://localhost:5700/network/status (internal)
#   SELECT true FROM address_book LIMIT 1    (PostgreSQL)
#
# At 200 req/s inbound:
#   400 additional internal HTTP requests/s
#   200 additional DB queries/s
#
# Monitor with: watch -n1 'ss -s'  (connection counts)
# and:          top / pprof         (CPU/goroutine counts)
# Expected: CPU and goroutine count rise >30% above baseline within seconds.
```