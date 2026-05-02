### Title
Self-Referential Readiness Health Check with `SkipOnErr: false` Enables Load-Balancer Eviction via Loopback Saturation

### Summary
The `network` readiness check in `NewHealthController()` makes loopback HTTP calls back to the same server process it is embedded in. With `SkipOnErr: false` and no retry logic, any transient failure of those loopback calls — including timeouts caused by an attacker flooding the server's goroutine/connection pool — is immediately treated as a hard health failure, returning HTTP 503 on `/health/readiness` and causing load balancers to evict the node from rotation.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/health.go`, `NewHealthController()`, lines 44–49:
```go
{
    Name:      "network",
    Timeout:   time.Second * 10,
    SkipOnErr: false,
    Check:     checkNetworkStatus(rosettaConfig.Port),
},
```

`checkNetworkStatus()`, lines 80–100:
```go
func checkNetworkStatus(port uint16) func(ctx context.Context) error {
    serverUrl := fmt.Sprintf("http://localhost:%d", port)
    cfg := client.NewConfiguration(serverUrl, "readiness-check", nil)
    rosettaClient := client.NewAPIClient(cfg)

    return func(ctx context.Context) (checkErr error) {
        networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, &types.MetadataRequest{})
        if err != nil {
            log.Errorf("Readiness check, /network/list failed: %v", err)
            return err   // ← returned immediately, no retry
        }
        network := networkList.NetworkIdentifiers[0]
        _, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, &types.NetworkRequest{...})
        if err != nil {
            log.Errorf("Readiness check, /network/status failed: %v", err)
            return err   // ← returned immediately, no retry
        }
        return
    }
}
```

**Root cause and failed assumption:**

The design assumes the loopback path (`localhost:{port}`) is always available and fast. In reality, the health check competes for the same goroutine pool, TCP accept queue, and HTTP handler capacity as external traffic. When the server is saturated:

1. The loopback TCP connection may queue behind thousands of attacker connections.
2. Even if connected, the `/network/list` or `/network/status` handler may not be scheduled within the 10-second context deadline.
3. The returned error propagates directly to the `hellofresh/health-go` framework.
4. Because `SkipOnErr: false`, the framework marks the overall readiness status as `StatusUnavailable`.
5. The `/health/readiness` endpoint returns HTTP 503.
6. The load balancer removes the node from rotation.

There is no retry, no circuit-breaker, no minimum consecutive-failure threshold, and no fallback. A single check cycle failure is sufficient.

**Why existing checks are insufficient:**

- The 10-second `Timeout` only bounds how long the check waits; it does not prevent the timeout from being reached under load.
- The `hellofresh/health-go` library's `SkipOnErr: false` is a binary flag — error → unavailable, with no grace period or count threshold.
- No rate-limiting or connection-limiting is applied to the `/health/readiness` endpoint itself, so the attacker can also directly poll it to observe and confirm the failure state.

### Impact Explanation
A successful attack causes the Rosetta mirror node to be removed from load balancer rotation, making it unreachable to all legitimate clients for the duration of the attack. Because the health check is self-referential, the attack does not need to fully exhaust server resources — it only needs to delay the loopback response past 10 seconds. This is a targeted availability attack against a specific node in a distributed network, potentially enabling selective partition of that node from the broader Hedera/Hiero ecosystem.

### Likelihood Explanation
The attacker requires no credentials, no API keys, and no knowledge of internal state — only the ability to send unauthenticated HTTP POST requests to the public Rosetta API port. Standard HTTP flood tools (e.g., `wrk`, `hey`, `ab`) are sufficient. The attack is repeatable and sustainable: as long as the flood continues, the health check will keep failing and the node will remain evicted. Once the flood stops, the node recovers automatically, but the attacker can restart at will.

### Recommendation
1. **Decouple the health check from the live request path.** Instead of making loopback HTTP calls, expose an internal in-process readiness flag (e.g., an atomic boolean set by the network service after successful initialization) that the health check reads directly, with no network round-trip.
2. **If loopback calls are retained, add a consecutive-failure threshold** (e.g., fail readiness only after N consecutive failures) to tolerate transient load spikes.
3. **Set `SkipOnErr: true`** on the `network` check, or implement a custom check that distinguishes between "server is initializing" (hard fail) and "server is temporarily busy" (skip/warn).
4. **Apply connection rate-limiting** on the Rosetta HTTP listener to bound the number of concurrent connections an external source can hold open.

### Proof of Concept
```bash
# 1. Start the Rosetta mirror node normally; confirm it is healthy:
curl -s http://<node>:<port>/health/readiness
# → {"status":"OK",...}

# 2. Flood the server with concurrent requests (no auth required):
wrk -t 50 -c 500 -d 60s \
  -s post.lua \          # POST /network/list with minimal JSON body
  http://<node>:<port>/network/list

# 3. While flood is running, poll the readiness endpoint:
watch -n 1 'curl -s -o /dev/null -w "%{http_code}" http://<node>:<port>/health/readiness'
# → Transitions from 200 to 503 within one health-check cycle (≤10 s)

# 4. Confirm load balancer eviction by observing that the node stops
#    receiving traffic from the upstream LB (check LB access logs or
#    active connection counts drop to zero on this node).

# 5. Stop the flood; within the next health-check cycle the node
#    recovers and is re-added to rotation — confirming the attack
#    is repeatable on demand.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** rosetta/app/middleware/health.go (L44-49)
```go
		{
			Name:      "network",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     checkNetworkStatus(rosettaConfig.Port),
		},
```

**File:** rosetta/app/middleware/health.go (L80-100)
```go
func checkNetworkStatus(port uint16) func(ctx context.Context) error {
	serverUrl := fmt.Sprintf("http://localhost:%d", port)
	cfg := client.NewConfiguration(serverUrl, "readiness-check", nil)
	rosettaClient := client.NewAPIClient(cfg)

	return func(ctx context.Context) (checkErr error) {
		networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, &types.MetadataRequest{})
		if err != nil {
			log.Errorf("Readiness check, /network/list failed: %v", err)
			return err
		}

		network := networkList.NetworkIdentifiers[0]
		_, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, &types.NetworkRequest{NetworkIdentifier: network})
		if err != nil {
			log.Errorf("Readiness check, /network/status failed: %v", err)
			return err
		}

		return
	}
```
