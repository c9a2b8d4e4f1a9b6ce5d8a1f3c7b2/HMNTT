### Title
Unauthenticated Flood of `GET /health/readiness` Causes Recursive Amplification Loop, Silencing the Readiness Signal Used to Detect Hashgraph Anomalies

### Summary
`checkNetworkStatus()` in `rosetta/app/middleware/health.go` registers a health check that, on every single `GET /health/readiness` request, makes two synchronous outbound HTTP calls back to the same Rosetta server process (`NetworkList` + `NetworkStatus`). Because the `/health/readiness` endpoint is completely unprotected by any rate-limiting or concurrency control at any layer, an unprivileged attacker can flood it to create a 3× request amplification loop that exhausts server goroutines and database connections, causing the internal calls to time out, the readiness check to return HTTP 503, and the pod to be removed from load balancing — permanently suppressing the readiness signal that operators rely on to detect chain-history anomalies.

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

The returned closure is registered as the `network` health check with `Timeout: time.Second * 10` and `SkipOnErr: false`. The `hellofresh/health-go` v4 library runs all registered checks **synchronously on every request** — there is no result caching or concurrency gate configured.

**Root cause — three compounding failures:**

1. **No rate limiting on `/health/readiness` at any layer.** The Traefik middleware chain (rate limit: 10 req/s, in-flight: 5) is defined in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166 and applied only to the ingress paths `/rosetta/account`, `/rosetta/block`, etc. — `/health/readiness` is not in that list. Furthermore, `global.middleware` defaults to `false` (line 95), so the middleware chain is disabled unless explicitly enabled. There is zero application-level rate limiting in the Go code.

2. **Self-referential amplification loop.** Each `GET /health/readiness` causes two HTTP calls back to `localhost:{port}` — the same process. One external request becomes three server-side requests (1 health + 1 NetworkList + 1 NetworkStatus). `NetworkStatus` (network_service.go lines 59–88) issues three real database queries (genesis block, latest block, address book entries).

3. **No concurrency control.** `client.NewConfiguration(serverUrl, "readiness-check", nil)` passes `nil` for the HTTP client, using Go's default `http.DefaultTransport` with no connection pool cap relevant to this self-loop. Under flood, goroutines and DB connections pile up.

**Exploit flow:**

Under sustained flood, the server's goroutine pool and DB connection pool saturate. The internal `NetworkList`/`NetworkStatus` calls begin to queue behind each other. The 10-second timeout fires before they complete. `checkNetworkStatus` returns an error; `SkipOnErr: false` causes the overall readiness check to fail; `hellofresh/health-go` returns HTTP 503. Kubernetes marks the pod `NotReady` and removes it from the Service endpoints. The readiness signal is now permanently suppressed for the duration of the attack.

### Impact Explanation

The readiness check's `NetworkStatus` call is the only automated mechanism that verifies the Rosetta node can reach the latest Hashgraph block and its peer address book. When an attacker suppresses this signal via flood, operators lose the ability to distinguish between "service is under DoS" and "service is failing because chain history has been tampered with or the node is stuck." A concurrent tampering event (e.g., a forked or rolled-back block sequence causing `RetrieveLatest` to return stale data) would produce the same 503 readiness response as the flood, making the two indistinguishable. Kubernetes HPA and alerting rules (e.g., `RosettaNoPodsReady` in `values.yaml` lines 202–212) fire on pod readiness, not on the reason for failure, so operators receive a generic "no pods ready" alert with no indication of tampering.

### Likelihood Explanation

No authentication, API key, or network-level restriction is required to reach `/health/readiness`. The endpoint is exposed on the same port as the Rosetta API (default 5700). A single attacker with a modest HTTP flood tool (e.g., `wrk`, `hey`, or `ab`) can sustain the amplification loop. The attack is repeatable, requires no special knowledge of the system, and is effective even at moderate request rates because each request consumes three server-side processing slots. The Traefik middleware that could mitigate this is disabled by default.

### Recommendation

1. **Add application-level rate limiting to `/health/readiness`.** Wrap the handler with a token-bucket or semaphore that caps concurrent health checks (e.g., 1–2 in-flight at a time), independent of the Traefik middleware.

2. **Cache health check results.** Use `hellofresh/health-go` v4's `MaxTimeInFlight` or a simple `sync.Mutex` + TTL cache (e.g., 5 seconds) so that concurrent or rapid requests reuse the last result rather than spawning new internal HTTP calls.

3. **Break the self-referential loop.** Instead of making HTTP calls back to `localhost`, call the `networkAPIService.NetworkList` and `networkAPIService.NetworkStatus` methods directly (in-process), eliminating the amplification entirely.

4. **Enable and extend the Traefik middleware to health paths**, or enforce `global.middleware: true` in production values.

### Proof of Concept

```bash
# Precondition: Rosetta server running on port 5700, no Traefik middleware active
# (global.middleware defaults to false)

# Step 1: Confirm baseline readiness
curl -s http://<rosetta-host>:5700/health/readiness
# Expected: HTTP 200, {"status":"OK",...}

# Step 2: Flood /health/readiness from a single unprivileged client
hey -z 60s -c 50 -q 0 http://<rosetta-host>:5700/health/readiness &

# Step 3: Observe readiness degradation within seconds
watch -n1 'curl -s -o /dev/null -w "%{http_code}" http://<rosetta-host>:5700/health/readiness'
# Transitions from 200 → 503 as goroutine/DB pool saturates

# Step 4: Confirm Kubernetes marks pod NotReady
kubectl get pods -l app.kubernetes.io/component=rosetta -w
# Pod transitions to 0/1 Ready

# Step 5: Confirm operator alert fires on generic "no pods ready" — no tampering signal visible
# RosettaNoPodsReady PrometheusRule triggers; no distinction from a tampering-induced failure
```