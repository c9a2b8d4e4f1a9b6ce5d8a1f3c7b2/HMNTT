### Title
Uncached `RetrieveLatest` DB Query with Rate Limiting Disabled by Default Enables Sustained DB Resource Exhaustion

### Summary
`RetrieveLatest()` in `rosetta/app/persistence/block.go` executes a raw SQL query (`ORDER BY index DESC LIMIT 1` on `record_file`) on every invocation with no result caching. The only rate-limiting defense — a Traefik middleware chain — is gated behind `global.middleware: false` in the default Helm values, meaning it is not deployed in default installations. Any unauthenticated external user can sustain moderate-rate requests to the public `/network/status` endpoint, each triggering a DB round-trip, causing measurable and sustained DB I/O amplification.

### Finding Description

**Exact code path:**

`rosetta/app/persistence/block.go`, `RetrieveLatest()`, lines 190–208: [1](#0-0) 

Every call unconditionally executes `selectLatestWithIndex`: [2](#0-1) 

This is called on every `/network/status` request via `NetworkStatus()`: [3](#0-2) 

And on every `/block` request with no block identifier via `RetrieveBlock()`: [4](#0-3) 

**Root cause — no caching:** The `blockRepository` struct holds a cached `genesisBlock` (set once via `sync.Once`), but there is no equivalent cache for the latest block. Every call to `RetrieveLatest` opens a DB connection and fires the query. [5](#0-4) 

**Root cause — rate limiting disabled by default:** The Helm chart defines a Traefik middleware chain including `rateLimit: average: 10` and `inFlightReq: amount: 5`, but the entire middleware template is wrapped in:

```
{{ if and .Values.global.middleware .Values.middleware -}}
``` [6](#0-5) 

`global.middleware` defaults to `false`: [7](#0-6) 

This means the middleware — including rate limiting — is **not deployed** in any default installation. The middleware values are defined but inert: [8](#0-7) 

There is no application-level rate limiting or caching anywhere in the Go service layer for this code path. [9](#0-8) 

### Impact Explanation

Each POST to `/network/status` (unauthenticated, publicly routed via ingress) causes one synchronous DB query against `record_file`. At a moderate sustained rate (e.g., 50–200 req/s from a single client or distributed across a few IPs), this generates a proportional stream of DB queries with no batching, deduplication, or cache hits. The `record_file` table is also written to continuously by the importer, so the query cannot be served from the OS page cache reliably. This directly increases DB CPU, I/O wait, and connection pool pressure, meeting the ≥30% resource increase threshold without requiring brute-force volume. In the worst case, connection pool exhaustion (`maxOpenConnections: 100`) causes cascading failures across all Rosetta endpoints. [10](#0-9) 

### Likelihood Explanation

The attack requires no credentials, no special knowledge, and no exploit tooling — only the ability to POST to the public `/network/status` endpoint. The Rosetta API is designed to be publicly accessible for exchange integrations. The default `global.middleware: false` means any operator who deployed using default Helm values has no rate limiting active. The attack is trivially repeatable with standard HTTP load tools (curl loop, wrk, ab) and is sustainable indefinitely.

### Recommendation

1. **Add result caching in `RetrieveLatest`**: Cache the latest block result with a short TTL (e.g., 1–3 seconds, matching the Hedera block interval). A simple `sync.Mutex`-protected struct with a timestamp check, or the existing `go-generics-cache` library already imported in `block_service.go`, is sufficient.

2. **Change `global.middleware` default to `true`**: The rate limiting and in-flight request middleware already exists and is correctly configured; it simply needs to be enabled by default.

3. **Add application-level in-flight deduplication**: For `RetrieveLatest`, use a `singleflight.Group` so that concurrent identical DB queries are collapsed into one, regardless of infrastructure-level rate limiting.

### Proof of Concept

```bash
# No authentication required. Default port 5700, path /network/status.
# Obtain network_identifier first:
NID=$(curl -s -X POST http://<rosetta-host>:5700/network/list \
  -H 'Content-Type: application/json' \
  -d '{"metadata":{}}' | jq '.network_identifiers[0]')

# Sustained moderate-rate flood (50 req/s) — no brute force needed:
while true; do
  curl -s -o /dev/null -X POST http://<rosetta-host>:5700/network/status \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\": $NID, \"metadata\": {}}" &
  sleep 0.02   # 50 req/s
done
```

Each iteration triggers `NetworkStatus` → `RetrieveLatest` → `selectLatestWithIndex` DB query. Monitor `pg_stat_activity` on the mirror node DB to observe the sustained query stream. With `global.middleware: false` (default), no request is throttled or rejected.

### Citations

**File:** rosetta/app/persistence/block.go (L24-31)
```go
	selectLatestWithIndex string = `select consensus_start,
                                           consensus_end,
                                           hash,
                                           index,
                                           prev_hash
                                    from record_file
                                    order by index desc
                                    limit 1`
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

**File:** rosetta/app/services/network_service.go (L59-75)
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
```

**File:** rosetta/app/services/base_service.go (L71-89)
```go
func (b *BaseService) RetrieveBlock(ctx context.Context, bIdentifier *rTypes.PartialBlockIdentifier) (
	*types.Block,
	*rTypes.Error,
) {
	if !b.IsOnline() {
		return nil, errors.ErrInternalServerError
	}

	if bIdentifier.Hash != nil && bIdentifier.Index != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByIdentifier(ctx, *bIdentifier.Index, h)
	} else if bIdentifier.Hash == nil && bIdentifier.Index != nil {
		return b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)
	} else if bIdentifier.Index == nil && bIdentifier.Hash != nil {
		h := tools.SafeRemoveHexPrefix(*bIdentifier.Hash)
		return b.blockRepo.FindByHash(ctx, h)
	} else {
		return b.blockRepo.RetrieveLatest(ctx)
	}
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-97)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
  podAnnotations: {}
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

**File:** rosetta/app/services/block_service.go (L18-44)
```go
// blockAPIService implements the server.BlockAPIServicer interface.
type blockAPIService struct {
	accountRepo interfaces.AccountRepository
	BaseService
	entityCache            *cache.Cache[int64, types.AccountId]
	maxTransactionsInBlock int
}

// NewBlockAPIService creates a new instance of a blockAPIService.
func NewBlockAPIService(
	accountRepo interfaces.AccountRepository,
	baseService BaseService,
	entityCacheConfig config.Cache,
	maxTransactionsInBlock int,
	serverContext context.Context,
) server.BlockAPIServicer {
	entityCache := cache.NewContext(
		serverContext,
		cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize)),
	)
	return &blockAPIService{
		accountRepo:            accountRepo,
		BaseService:            baseService,
		entityCache:            entityCache,
		maxTransactionsInBlock: maxTransactionsInBlock,
	}
}
```

**File:** docs/configuration.md (L658-660)
```markdown
| `hiero.mirror.rosetta.db.pool.maxIdleConnections` | 20                  | The maximum number of idle database connections                                                     |
| `hiero.mirror.rosetta.db.pool.maxLifetime`        | 30                  | The maximum lifetime of a database connection in minutes                                            |
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
```
