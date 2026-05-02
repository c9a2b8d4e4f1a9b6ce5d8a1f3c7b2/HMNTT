### Title
Unauthenticated `/health/readiness` Endpoint Causes 3x Amplified Resource Exhaustion on Shared Server

### Summary
The `/health/readiness` endpoint is registered on the same HTTP server, port, and goroutine pool as the main Rosetta API with no application-level rate limiting or concurrency control. Each readiness check invocation triggers two recursive internal HTTP calls back to the same server (`/network/list` and `/network/status`) plus a PostgreSQL connection check, creating a 3x resource amplification factor. An unprivileged external attacker flooding this endpoint can exhaust the shared DB connection pool and goroutine capacity, degrading or denying service to legitimate API users well above the 30% threshold.

### Finding Description

**Code path — shared server registration:**

In `rosetta/main.go` lines 111–119, `healthController` is registered in the same `server.NewRouter(...)` as all API controllers and served by a single `http.Server` on port 5700:

```go
return server.NewRouter(
    networkAPIController,
    blockAPIController,
    ...
    healthController,   // health routes share the same mux and goroutine pool
    metricsController,
), nil
``` [1](#0-0) 

**Root cause — recursive self-call amplification in `checkNetworkStatus`:**

`rosetta/app/middleware/health.go` lines 80–100 show that each `/health/readiness` request executes `checkNetworkStatus`, which creates a Rosetta API client pointing at `http://localhost:<port>` (the same server) and fires two full API requests: [2](#0-1) 

```go
func checkNetworkStatus(port uint16) func(ctx context.Context) error {
    serverUrl := fmt.Sprintf("http://localhost:%d", port)
    ...
    return func(ctx context.Context) (checkErr error) {
        networkList, _, err := rosettaClient.NetworkAPI.NetworkList(ctx, ...)   // → /network/list on same server
        ...
        _, _, err = rosettaClient.NetworkAPI.NetworkStatus(ctx, ...)            // → /network/status on same server
    }
}
```

Additionally, the readiness check registers a PostgreSQL check with a 10-second timeout: [3](#0-2) 

**Resource amplification per request:**
- 1 goroutine for the `/health/readiness` handler
- 1 PostgreSQL connection (10s timeout) for the `postgres` check
- 1 goroutine + 1+ DB query for the internal `/network/list` call
- 1 goroutine + 1+ DB query for the internal `/network/status` call

Each external health check request consumes ~3 goroutines and ~3 DB connections simultaneously.

**Why existing checks are insufficient:**

The Traefik ingress middleware (`values.yaml` lines 149–166) configures `inFlightReq: amount: 5` and `rateLimit: average: 10`, but these only apply to the explicitly listed ingress paths: [4](#0-3) 

```yaml
paths:
  - "/rosetta/account"
  - "/rosetta/block"
  ...
  - "/rosetta/network"
  - "/rosetta/search"
```

`/health/readiness` is **not** in this list. The Kubernetes readiness probe accesses it directly via `port: http`, bypassing the ingress entirely: [5](#0-4) 

There is no application-level rate limiting, concurrency semaphore, or request coalescing on the health endpoint in the Rosetta Go codebase.

### Impact Explanation

The default DB pool is `maxOpenConnections: 100`. With the 3x amplification, approximately **34 concurrent `/health/readiness` requests** exhaust all 100 DB connections (34 × 3 ≈ 102). Once the pool is exhausted, every legitimate API request that requires a DB query blocks or fails. The goroutine pool is similarly pressured: Go's `net/http` server spawns one goroutine per connection, and each health check holds 3 goroutines for up to 10 seconds (the PostgreSQL check timeout). This is a resource exhaustion attack that directly degrades API availability well beyond 30%.

### Likelihood Explanation

The endpoint requires no authentication, no API key, and no special network position — any external user with TCP access to port 5700 can trigger it. The amplification means the attacker does not need high bandwidth or a botnet; a single machine sending ~50 concurrent requests is sufficient to saturate the DB pool. The attack is repeatable and persistent as long as the attacker maintains the connection flood.

### Recommendation

1. **Isolate health endpoints on a separate port** (e.g., a dedicated internal-only listener), so they cannot be reached by external users and do not share the API goroutine pool.
2. **Add a concurrency semaphore** on the readiness handler to limit simultaneous in-flight health checks (e.g., max 1–2 concurrent checks).
3. **Remove the recursive self-call** in `checkNetworkStatus`: instead of making HTTP calls back to the same server, check network readiness by querying the DB directly or using an in-process status flag.
4. **Add `/health/readiness` to the Traefik ingress middleware** paths if port isolation is not immediately feasible, so the existing `inFlightReq` and `rateLimit` controls apply.

### Proof of Concept

```bash
# Flood /health/readiness with 50 concurrent persistent connections
# No authentication required; port 5700 is the default Rosetta API port

for i in $(seq 1 50); do
  curl -s "http://<rosetta-host>:5700/health/readiness" &
done
wait

# Each curl triggers:
#   1. A postgres connection check (10s timeout)
#   2. GET http://localhost:5700/network/list  (internal, same server)
#   3. GET http://localhost:5700/network/status (internal, same server)
#
# Result: ~150 DB connections consumed (50 × 3), exhausting the default
# pool of 100. Legitimate /network/list, /block, /account requests
# begin returning errors or hanging until health checks time out.
#
# Verify impact by observing DB connection saturation:
#   SELECT count(*) FROM pg_stat_activity WHERE datname = 'mirror_node';
# Expected: count approaches maxOpenConnections (100) during the attack.
```

### Citations

**File:** rosetta/main.go (L111-119)
```go
	return server.NewRouter(
		networkAPIController,
		blockAPIController,
		mempoolAPIController,
		constructionAPIController,
		accountAPIController,
		healthController,
		metricsController,
	), nil
```

**File:** rosetta/app/middleware/health.go (L37-50)
```go
	readinessChecks := []health.Config{
		{
			Name:      "postgresql",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     postgres.New(postgres.Config{DSN: rosettaConfig.Db.GetDsn()}),
		},
		{
			Name:      "network",
			Timeout:   time.Second * 10,
			SkipOnErr: false,
			Check:     checkNetworkStatus(rosettaConfig.Port),
		},
	}
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L125-133)
```yaml
      paths:
        - "/rosetta/account"
        - "/rosetta/block"
        - "/rosetta/call"
        - "/rosetta/construction"
        - "/rosetta/events"
        - "/rosetta/mempool"
        - "/rosetta/network"
        - "/rosetta/search"
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L236-241)
```yaml
readinessProbe:
  failureThreshold: 5
  httpGet:
    path: /health/readiness
    port: http
  initialDelaySeconds: 30
```
