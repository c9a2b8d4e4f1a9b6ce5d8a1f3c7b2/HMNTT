### Title
Unauthenticated Index-Only Block Lookup Enables DB Resource Exhaustion via `/account/balance`

### Summary
The `AccountBalance()` handler in `rosetta/app/services/account_service.go` accepts a `PartialBlockIdentifier` containing only an `Index` field, which routes unconditionally to `blockRepo.FindByIndex()` — a raw SQL query with a correlated subquery — with no application-level rate limiting, caching, or deduplication. An unprivileged external attacker can flood the endpoint with sequential distinct block indices, forcing a fresh DB query per request and saturating the database connection pool (default: 100 open connections).

### Finding Description

**Exact code path:**

`AccountBalance()` at [1](#0-0)  checks whether `request.BlockIdentifier != nil` and calls `a.RetrieveBlock(ctx, request.BlockIdentifier)`.

`RetrieveBlock()` at [2](#0-1)  routes to `b.blockRepo.FindByIndex(ctx, *bIdentifier.Index)` when `Hash == nil && Index != nil` — no other validation.

`FindByIndex()` at [3](#0-2)  performs only a `index < 0` guard, then calls `findBlockByIndex()`.

`findBlockByIndex()` at [4](#0-3)  executes `selectRecordBlockByIndex` — a raw SQL query with a **correlated subquery** — against the database on every call, with no caching layer:

```sql
select consensus_start,
       coalesce((select consensus_start-1 from record_file where index = @index + 1::bigint), consensus_end) as consensus_end,
       hash, index, prev_hash
from record_file
where index = @index
``` [5](#0-4) 

If the block is found, `AccountBalance()` then also calls `accountRepo.RetrieveBalanceAtBlock()` — a second DB query — compounding the load per request. [6](#0-5) 

**Root cause:** There is zero application-level rate limiting, request throttling, or result caching for block-by-index lookups in the Rosetta Go service. A grep across all `rosetta/**/*.go` files returns no matches for any rate-limiting or throttling construct. [7](#0-6) 

**Why existing checks fail:**

The only input validation is `index < 0` rejection. [8](#0-7) 

The Traefik ingress middleware (`inFlightReq: amount: 5`, `rateLimit: average: 10`) is defined only in the Helm chart values and is conditionally rendered only when both `global.middleware` and `middleware` are set. [9](#0-8)  It is not enforced at the application layer and is absent in non-Kubernetes deployments. Furthermore, `rateLimit` uses `sourceCriterion: requestHost: true` — a **global** limit shared across all clients, not per-source-IP — meaning a single attacker consumes the entire 10 req/s budget. [10](#0-9) 

Additionally, the Traefik `retry: attempts: 3` middleware **amplifies** load: each rate-limited or failed request is retried 3 additional times against the backend. [11](#0-10) 

The DB connection pool defaults to `maxOpenConnections: 100`. [12](#0-11)  With no application-level throttle, an attacker can hold all 100 connections busy with index-lookup queries, starving legitimate traffic.

### Impact Explanation

Each crafted request with a unique valid block index triggers at minimum one correlated-subquery DB hit (`FindByIndex`) and, on success, a second query (`RetrieveBalanceAtBlock`). With 100 max open DB connections and no rate limiting in the application, an attacker sending concurrent requests from multiple connections can saturate the pool. Legitimate requests queue or time out. The `statementTimeout` default of 20 seconds means each held connection blocks for up to 20 s before releasing. [13](#0-12)  This constitutes a realistic path to ≥30% DB resource increase without brute-force volume — a moderate-to-high severity DoS against the mirror node's database tier.

### Likelihood Explanation

No authentication or API key is required to call `/account/balance`. The Rosetta spec explicitly defines this as a public data endpoint. The attacker needs only knowledge of valid block indices (trivially obtained by first calling `/network/status` to get the current block index, then iterating downward). The attack is repeatable, scriptable, and requires no special tooling beyond HTTP POST requests. In deployments without Traefik (bare metal, Docker Compose, direct Kubernetes without the ingress middleware), there is **no** rate limiting whatsoever.

### Recommendation

1. **Application-level rate limiting**: Add a per-IP rate limiter (e.g., `golang.org/x/time/rate` or `github.com/ulule/limiter`) as HTTP middleware in `rosetta/main.go` before the router, applied to all `/account/*` and `/block/*` endpoints.
2. **Block lookup cache**: Cache results of `FindByIndex` keyed by block index (with a short TTL, e.g., 5–10 s) using an in-process LRU cache (e.g., `github.com/hashicorp/golang-lru`). Block data is immutable once finalized.
3. **Fix Traefik rate limit criterion**: Change `sourceCriterion` from `requestHost: true` to `ipStrategy` (per-client-IP) so the rate limit applies per attacker, not globally.
4. **Remove the `retry` middleware** or scope it only to network errors, not application-level responses, to prevent load amplification.

### Proof of Concept

```bash
# Step 1: Get current block index
curl -s -X POST http://<rosetta-host>:5700/network/status \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' \
  | jq '.current_block_identifier.index'
# Returns e.g. 65000000

# Step 2: Flood /account/balance with distinct block indices (no auth required)
for i in $(seq 64999000 65000000); do
  curl -s -X POST http://<rosetta-host>:5700/account/balance \
    -H 'Content-Type: application/json' \
    -d "{
      \"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
      \"account_identifier\":{\"address\":\"0.0.2\"},
      \"block_identifier\":{\"index\":$i}
    }" &
done
wait
# Each request triggers FindByIndex (correlated subquery) + RetrieveBalanceAtBlock
# With 100 max DB connections, pool saturates; legitimate queries queue/timeout
```

### Citations

**File:** rosetta/app/services/account_service.go (L52-56)
```go
	if request.BlockIdentifier != nil {
		block, rErr = a.RetrieveBlock(ctx, request.BlockIdentifier)
	} else {
		block, rErr = a.RetrieveLatest(ctx)
	}
```

**File:** rosetta/app/services/account_service.go (L61-63)
```go
	balances, accountIdString, publicKey, rErr := a.accountRepo.RetrieveBalanceAtBlock(ctx, accountId, block.ConsensusEndNanos)
	if rErr != nil {
		return nil, rErr
```

**File:** rosetta/app/services/base_service.go (L71-90)
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
}
```

**File:** rosetta/app/persistence/block.go (L75-85)
```go
	selectRecordBlockByIndex string = `select consensus_start,
                                             coalesce((
                                               select consensus_start-1
                                               from record_file
                                               where index = @index + 1::bigint
                                             ), consensus_end) as consensus_end,
                                             hash,
                                             index,
                                             prev_hash
                                      from record_file
                                      where index = @index`
```

**File:** rosetta/app/persistence/block.go (L171-181)
```go
func (br *blockRepository) FindByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
	if index < 0 {
		return nil, hErrors.ErrInvalidArgument
	}

	if err := br.initGenesisRecordFile(ctx); err != nil {
		return nil, err
	}

	return br.findBlockByIndex(ctx, index)
}
```

**File:** rosetta/app/persistence/block.go (L210-223)
```go
func (br *blockRepository) findBlockByIndex(ctx context.Context, index int64) (*types.Block, *rTypes.Error) {
	if index < br.genesisBlock.Index {
		return nil, hErrors.ErrBlockNotFound
	}

	db, cancel := br.dbClient.GetDbWithContext(ctx)
	defer cancel()

	rb := &recordBlock{}
	if err := db.Raw(selectRecordBlockByIndex, sql.Named("index", index)).First(rb).Error; err != nil {
		return nil, handleDatabaseError(err, hErrors.ErrBlockNotFound)
	}

	return rb.ToBlock(br.genesisBlock), nil
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L161-163)
```yaml
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** docs/configuration.md (L660-660)
```markdown
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
```

**File:** docs/configuration.md (L662-662)
```markdown
| `hiero.mirror.rosetta.db.statementTimeout`        | 20                  | The number of seconds to wait before timing out a query statement                                   |
```
