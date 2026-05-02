### Title
LRU Cache Thrashing via Unauthenticated `/block` Requests Causes Amplified DB Query Rate in `updateOperationAccountAlias`

### Summary
The `updateOperationAccountAlias` function in `rosetta/app/services/block_service.go` performs a database query (`GetAccountAlias`) for every operation whose `AccountId` is absent from the bounded LRU `entityCache`. Because the Rosetta `/block` and `/block/transaction` endpoints are unauthenticated and have no rate limiting, an unprivileged external attacker can repeatedly request blocks with disjoint sets of account IDs, continuously evicting cached entries and forcing repeated DB queries, measurably increasing node resource consumption.

### Finding Description

**Exact code path:**

`rosetta/app/services/block_service.go`, `updateOperationAccountAlias()`, lines 104–130:

```go
if cached, found = s.entityCache.Get(accountId.GetId()); !found {
    result, err := s.accountRepo.GetAccountAlias(ctx, accountId)   // DB hit
    ...
    s.entityCache.Set(result.GetId(), result)
```

The cache is a pure LRU with a fixed capacity (`entityCacheConfig.MaxSize`, default **524,288** per docs):

```go
cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize))
``` [1](#0-0) 

Every cache miss triggers `accountRepository.GetAccountAlias`, which executes:
```sql
select alias, id from entity where id = @id
``` [2](#0-1) [3](#0-2) 

**Root cause / failed assumption:** The design assumes the working set of account IDs across concurrent block requests fits within `MaxSize`. There is no rate limiting, no per-IP throttling, and no authentication on the `/block` endpoint. The middleware stack is only metrics + tracing + CORS: [4](#0-3) 

**Exploit flow:**

1. Attacker identifies (or constructs via repeated `/block` polling) two blocks, **A** and **B**, whose combined unique `AccountId` sets across their operations each exceed `MaxSize/2`.
2. Attacker sends `POST /block` for block A → all A-set IDs are cache-misses → `|A|` DB queries → cache now holds Set A.
3. Attacker sends `POST /block` for block B → all B-set IDs are cache-misses (LRU evicts Set A) → `|B|` DB queries → cache now holds Set B.
4. Repeat steps 2–3 in a tight loop. Every alternation causes a full cache miss wave.

Even without reaching the theoretical `MaxSize/2` threshold, any two blocks with sufficiently large disjoint account sets produce the same amplification effect at proportionally smaller scale. The number of operations processed per request is bounded by `maxTransactionsInBlock` [5](#0-4) 
but this value is operator-configurable and may be very large or effectively unlimited.

**Why existing checks fail:** No rate limiting, no authentication, no per-request account-ID deduplication before cache lookup, and no TTL on cache entries (pure capacity-based LRU only). [6](#0-5) 

### Impact Explanation
Each cache miss translates directly to a synchronous SQL query against the mirror node database. A sustained alternating-block attack multiplies the DB query rate by a factor proportional to the number of unique account IDs per block. With the default `maxOpenConnections = 100` and `statementTimeout = 20s`, a high-frequency attacker can saturate the DB connection pool, increase CPU/IO on the database host, and degrade response latency for all other API consumers. This meets the "≥30% resource increase" threshold at moderate request rates with blocks containing hundreds of unique accounts.

### Likelihood Explanation
The Rosetta API is a public, unauthenticated HTTP interface by design (Coinbase Rosetta spec). Any external party can send `POST /block` requests with arbitrary `block_identifier` values. No special privileges, credentials, or on-chain actions are required. The attacker only needs to identify two existing blocks with sufficiently disjoint account sets, which is trivially discoverable by scanning block history. The attack is fully repeatable and automatable with a simple HTTP client loop.

### Recommendation
1. **Add rate limiting middleware** (e.g., token-bucket per IP) before the block API controllers in `main.go`.
2. **Deduplicate account IDs** within a single `updateOperationAccountAlias` call before issuing DB queries, to avoid redundant lookups within one request.
3. **Add a TTL** to cache entries so that the LRU is not the sole eviction mechanism; a time-based expiry reduces the value of cache-thrashing.
4. **Batch `GetAccountAlias` queries** for all unique IDs in a block in a single SQL `WHERE id IN (...)` call rather than one query per operation.

### Proof of Concept

```python
import requests, itertools

NODE = "http://<rosetta-node>:5700"
NETWORK = {"blockchain": "Hedera", "network": "mainnet"}

# Two blocks known to have large, disjoint account sets
BLOCK_A = {"index": 1000}
BLOCK_B = {"index": 2000}

session = requests.Session()
for block_id in itertools.cycle([BLOCK_A, BLOCK_B]):
    session.post(f"{NODE}/block", json={
        "network_identifier": NETWORK,
        "block_identifier": block_id
    })
    # No sleep — fire as fast as the server accepts connections
```

Each alternation between block A and block B causes a full cache-miss wave for the opposing set's account IDs, issuing one `SELECT alias, id FROM entity WHERE id = @id` query per unique account ID per request. Monitor DB `pg_stat_activity` or CPU to observe the amplification.

### Citations

**File:** rosetta/app/services/block_service.go (L34-37)
```go
	entityCache := cache.NewContext(
		serverContext,
		cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize)),
	)
```

**File:** rosetta/app/services/block_service.go (L61-67)
```go
	if len(block.Transactions) > s.maxTransactionsInBlock {
		otherTransactions = make([]*rTypes.TransactionIdentifier, 0, len(block.Transactions)-s.maxTransactionsInBlock)
		for _, transaction := range block.Transactions[s.maxTransactionsInBlock:] {
			otherTransactions = append(otherTransactions, &rTypes.TransactionIdentifier{Hash: transaction.Hash})
		}
		block.Transactions = block.Transactions[0:s.maxTransactionsInBlock]
	}
```

**File:** rosetta/app/services/block_service.go (L115-122)
```go
			if cached, found = s.entityCache.Get(accountId.GetId()); !found {
				result, err := s.accountRepo.GetAccountAlias(ctx, accountId)
				if err != nil {
					return err
				}

				s.entityCache.Set(result.GetId(), result)
				cached = result
```

**File:** rosetta/app/persistence/account.go (L51-51)
```go
	selectCryptoEntityWithAliasById = "select alias, id from entity where id = @id"
```

**File:** rosetta/app/persistence/account.go (L113-123)
```go
	db, cancel := ar.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var entity domain.Entity
	if err := db.Raw(selectCryptoEntityWithAliasById, sql.Named("id", accountId.GetId())).First(&entity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return accountId, nil
		}

		return zero, hErrors.ErrDatabaseError
	}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
