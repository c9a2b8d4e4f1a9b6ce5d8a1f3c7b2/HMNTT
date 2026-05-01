### Title
Unauthenticated `/network/status` Endpoint Exhausts DB Connection Pool via Concurrent Flooding (No Rate Limiting by Default)

### Summary
The `NetworkStatus()` handler in `rosetta/app/services/network_service.go` issues 2–3 sequential database queries per request (`RetrieveLatest` + up to 2 `Entries` queries) with no application-level rate limiting. The Traefik-based rate limiting middleware is disabled by default (`global.middleware: false`). Any unauthenticated external caller can flood the endpoint with concurrent requests, exhausting the finite DB connection pool (default: 100 connections) and causing denial-of-service for all legitimate callers.

### Finding Description

**Exact code path:**

`NetworkStatus()` at [1](#0-0)  makes three calls per request:

1. `n.RetrieveGenesis(ctx)` — delegates to `blockRepository.RetrieveGenesis()` [2](#0-1)  which calls `initGenesisRecordFile` guarded by `sync.Once` [3](#0-2)  — **cached after first call, no DB hit on subsequent requests**.

2. `n.RetrieveLatest(ctx)` — always executes `selectLatestWithIndex` against the DB [4](#0-3)  — **1 DB query per request, always**.

3. `n.addressBookEntryRepo.Entries(ctx)` — always executes `latestNodeServiceEndpoints` for file 101 and potentially file 102 [5](#0-4)  — **1–2 DB queries per request, always**.

**Root cause — no application-level rate limiting:**

The Go HTTP server middleware chain in `main.go` is: `MetricsMiddleware → TracingMiddleware → CorsMiddleware → router` [6](#0-5)  — no rate limiting, no concurrency cap, no authentication.

**Existing check is insufficient — Traefik middleware is opt-in and disabled by default:**

The Helm chart defines Traefik middleware with `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per host [7](#0-6) , but the middleware template is gated on `global.middleware` being `true` [8](#0-7) , which defaults to `false` [9](#0-8) . In the default deployment, no rate limiting exists at any layer.

**DB connection pool is finite:**

The pool defaults to `maxOpenConnections: 100` with a `statementTimeout` of 20 seconds [10](#0-9) . Each concurrent `/network/status` request holds 1–2 DB connections for up to 20 seconds. With 50–100 concurrent attackers, the pool is fully saturated.

### Impact Explanation

When the DB connection pool is exhausted, all subsequent DB-backed endpoints (block queries, account queries, construction) return `ErrDatabaseError` to legitimate callers. The Rosetta node becomes effectively unavailable for exchanges or integrators relying on it. Since the Rosetta API is used by exchanges for blockchain data integration (per the README), this constitutes a meaningful service disruption. Severity is medium/griefing: no funds are at risk, but service availability is fully compromised for the duration of the attack.

### Likelihood Explanation

The attack requires no credentials, no special knowledge, and no on-chain resources — only the ability to send HTTP POST requests to a publicly reachable port (default 5700). A single attacker with a modest number of concurrent connections (e.g., 100 goroutines in a Go script) can saturate the pool. The attack is trivially repeatable and sustainable indefinitely. Deployments that skip the Helm chart (e.g., bare Docker or custom Kubernetes manifests) will have no Traefik protection regardless of chart defaults.

### Recommendation

1. **Add application-level concurrency limiting** in `main.go` using `golang.org/x/net/netutil` or a semaphore middleware before the router, independent of infrastructure.
2. **Cache the `Entries` result** in `addressBookEntryRepository` with a short TTL (e.g., matching `nodeRefreshInterval`, default 24h) using a `sync.RWMutex`-protected field, similar to how `genesisBlock` is cached with `sync.Once`.
3. **Enable the Traefik middleware by default** by changing `global.middleware` default to `true` in `values.yaml`.
4. **Add a per-endpoint DB query timeout** shorter than the global `statementTimeout` for lightweight status endpoints.

### Proof of Concept

```bash
# Flood /network/status with 200 concurrent unauthenticated requests
# (no credentials, no special headers required)
seq 200 | xargs -P200 -I{} curl -s -o /dev/null -w "%{http_code}\n" \
  -X POST http://<rosetta-host>:5700/network/status \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}'

# Expected result after pool exhaustion:
# Legitimate callers receive 500 Internal Server Error (ErrDatabaseError)
# Attack is sustainable as long as requests keep arriving
```

Preconditions: Rosetta running in online mode (default), no Traefik middleware deployed (default `global.middleware: false`), DB pool at default size (100 connections).

### Citations

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

**File:** rosetta/app/persistence/block.go (L119-133)
```go
type blockRepository struct {
	dbClient         interfaces.DbClient
	genesisBlock     recordBlock
	once             sync.Once
	treasuryEntityId domain.EntityId
}

// NewBlockRepository creates an instance of a blockRepository struct
func NewBlockRepository(dbClient interfaces.DbClient, treasuryEntityId domain.EntityId) interfaces.BlockRepository {
	return &blockRepository{
		dbClient:         dbClient,
		genesisBlock:     recordBlock{ConsensusStart: genesisConsensusStartUnset},
		treasuryEntityId: treasuryEntityId,
	}
}
```

**File:** rosetta/app/persistence/block.go (L183-188)
```go
func (br *blockRepository) RetrieveGenesis(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}
	return br.genesisBlock.ToBlock(br.genesisBlock), nil
}
```

**File:** rosetta/app/persistence/block.go (L190-208)
```go
func (br *blockRepository) RetrieveLatest(ctx context.Context) (*types.Block, *rTypes.Error) {
	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectLatestWithIndex).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	if rb.Index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	return rb.ToBlock(br.genesisBlock), nil
}
```

**File:** rosetta/app/persistence/address_book_entry.go (L57-83)
```go
func (aber *addressBookEntryRepository) Entries(ctx context.Context) (*types.AddressBookEntries, *rTypes.Error) {
	db, cancel := aber.dbClient.GetDbWithContext(ctx)
	defer cancel()

	nodes := make([]nodeServiceEndpoint, 0)
	// address book file 101 has service endpoints for nodes, resort to file 102 if 101 doesn't exist
	for _, fileId := range []int64{aber.addressBook101.EncodedId, aber.addressBook102.EncodedId} {
		if err := db.Raw(
			latestNodeServiceEndpoints,
			sql.Named("file_id", fileId),
		).Scan(&nodes).Error; err != nil {
			log.Error("Failed to get latest node service endpoints", err)
			return nil, errors.ErrDatabaseError
		}

		if len(nodes) != 0 {
			break
		}
	}

	entries := make([]types.AddressBookEntry, 0, len(nodes))
	for _, node := range nodes {
		entries = append(entries, node.toAddressBookEntry())
	}

	return &types.AddressBookEntries{Entries: entries}, nil
}
```

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** docs/configuration.md (L658-662)
```markdown
| `hiero.mirror.rosetta.db.pool.maxIdleConnections` | 20                  | The maximum number of idle database connections                                                     |
| `hiero.mirror.rosetta.db.pool.maxLifetime`        | 30                  | The maximum lifetime of a database connection in minutes                                            |
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
| `hiero.mirror.rosetta.db.port`                    | 5432                | The port used to connect to the database                                                            |
| `hiero.mirror.rosetta.db.statementTimeout`        | 20                  | The number of seconds to wait before timing out a query statement                                   |
```
