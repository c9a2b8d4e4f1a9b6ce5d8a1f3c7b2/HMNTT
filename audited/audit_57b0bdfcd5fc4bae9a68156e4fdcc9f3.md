### Title
Unauthenticated `/health/readiness` Endpoint Enables Request Amplification DoS via Unbounded `NetworkStatus` and DB Query Fan-Out

### Summary
The `/health/readiness` endpoint in `rosetta/app/middleware/health.go` is publicly accessible with no rate limiting or authentication. Each inbound request unconditionally triggers two loopback HTTP calls (`/network/list` and `/network/status`) plus multiple PostgreSQL queries, creating a request-amplification effect. An unprivileged attacker can flood this endpoint to multiply internal resource consumption well beyond 30% of baseline.

### Finding Description
**Code path:**

`rosetta/app/middleware/health.go`, `checkNetworkStatus()`, lines 80–100: [1](#0-0) 

Each call to the `/health/readiness` handler invokes the closure returned by `checkNetworkStatus()`. That closure unconditionally performs:

1. `rosettaClient.NetworkAPI.NetworkList(ctx, ...)` — loopback HTTP POST to `http://localhost:{port}/network/list`
2. `rosettaClient.NetworkAPI.NetworkStatus(ctx, ...)` — loopback HTTP POST to `http://localhost:{port}/network/status`

`NetworkStatus` in `rosetta/app/services/network_service.go` lines 59–88 then executes: [2](#0-1) 

- `n.RetrieveGenesis(ctx)` → `blockRepository.initGenesisRecordFile` (cached via `sync.Once` after first call, so only 1 DB query total across all requests)
- `n.RetrieveLatest(ctx)` → `selectLatestWithIndex` SQL query on every single call (no caching)
- `n.addressBookEntryRepo.Entries(ctx)` → up to 2 SQL queries per call (tries address book file 101, then 102)

Additionally, the `postgresql` health check registered at line 42 opens a DB connection and runs a ping on every readiness request: [3](#0-2) 

**Root cause:** No rate limiting, no result caching between health-check invocations, and no HTTP connection limit on the server. A grep across all rosetta Go sources confirms zero rate-limiting or throttling code exists: [4](#0-3) 

The `hellofresh/health-go` library re-executes all registered check functions on every HTTP request to the handler — there is no built-in debounce or TTL cache.

The HTTP server in `rosetta/main.go` sets only timeout values; no `MaxConns` or similar limit is configured: [5](#0-4) 

**Amplification ratio per external request:**
- 2 internal loopback HTTP requests (each traversing the full metrics + tracing + CORS middleware stack)
- 1 PostgreSQL ping (health check)
- 1 `SELECT … FROM record_file ORDER BY index DESC LIMIT 1` (RetrieveLatest)
- 1–2 `SELECT … FROM address_book_entry …` queries (Entries)

### Impact Explanation
Each single unauthenticated GET to `/health/readiness` fans out into ≥4 internal operations (2 HTTP + ≥2 DB queries). At modest concurrency (e.g., 50 req/s), this generates 100 loopback HTTP requests/s and ≥100 DB queries/s against a node that would otherwise be idle or serving legitimate traffic. The `RetrieveLatest` and `Entries` queries are not trivially cheap — `selectLatestWithIndex` does a full descending index scan on `record_file`, and `latestNodeServiceEndpoints` is a multi-table join with aggregation. Sustained flooding can exhaust the PostgreSQL connection pool (`Pool.MaxOpenConnections`) and saturate Go's HTTP goroutine pool, degrading or denying service to legitimate Rosetta API consumers.

### Likelihood Explanation
The endpoint requires no credentials, no API key, and no prior knowledge beyond the server's port number (default is well-known from the Rosetta spec). The attack is trivially scriptable with `curl` or any HTTP load tool (`wrk`, `hey`, `ab`). No special network position is required — any internet-reachable node is vulnerable. The attack is repeatable and stateless.

### Recommendation
1. **Add a per-IP or global rate limiter** on `/health/readiness` (e.g., `golang.org/x/time/rate` or a middleware like `go-chi/httprate`) to cap requests to a few per second.
2. **Cache health-check results** with a short TTL (e.g., 5–10 seconds). The `hellofresh/health-go` library supports a `WithCacheDuration` option — use it so repeated requests within the TTL window return the cached status without re-executing checks.
3. **Restrict network exposure** of the health endpoints to internal/loopback interfaces or a separate port not exposed to the public internet, consistent with Kubernetes probe best practices.
4. **Set `http.Server.MaxHeaderBytes` and consider `nethttp.LimitListener`** to bound concurrent connections at the OS level.

### Proof of Concept
```bash
# Flood /health/readiness with 100 concurrent connections, 10000 total requests
# No authentication or special headers required
hey -n 10000 -c 100 http://<rosetta-node-ip>:<port>/health/readiness

# Observe on the server side:
# - PostgreSQL active connections spike (each request opens a DB connection for the pg health check)
# - CPU/goroutine count rises due to 2x loopback HTTP fan-out per request
# - Legitimate /network/status calls begin timing out as DB pool is exhausted
```

Each of the 10,000 requests triggers 2 internal HTTP calls and ≥2 DB queries, producing ≥20,000 internal HTTP requests and ≥20,000 DB queries from a single unauthenticated source.

### Citations

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

**File:** rosetta/app/middleware/health.go (L63-78)
```go
func (c *healthController) Routes() server.Routes {
	return server.Routes{
		{
			"liveness",
			"GET",
			livenessPath,
			c.livenessHealth.HandlerFunc,
		},
		{
			"readiness",
			"GET",
			readinessPath,
			c.readinessHealth.HandlerFunc,
		},
	}
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

**File:** rosetta/app/services/network_service.go (L59-88)
```go
func (n *networkAPIService) NetworkStatus(
	ctx context.Context,
	_ *rTypes.NetworkRequest,
) (*rTypes.NetworkStatusResponse, *rTypes.Error) {
	if !n.IsOnline() {
		return nil, errors.ErrEndpointNotSupportedInOfflineMode
	}

	genesisBlock, err := n.RetrieveGenesis(ctx)
	if err != nil {
		return nil, err
	}

	currentBlock, err := n.RetrieveLatest(ctx)
	if err != nil {
		return nil, err
	}

	peers, err := n.addressBookEntryRepo.Entries(ctx)
	if err != nil {
		return nil, err
	}

	return &rTypes.NetworkStatusResponse{
		CurrentBlockIdentifier: currentBlock.GetRosettaBlockIdentifier(),
		CurrentBlockTimestamp:  currentBlock.GetTimestampMillis(),
		GenesisBlockIdentifier: genesisBlock.GetRosettaBlockIdentifier(),
		Peers:                  peers.ToRosetta(),
	}, nil
}
```

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```
