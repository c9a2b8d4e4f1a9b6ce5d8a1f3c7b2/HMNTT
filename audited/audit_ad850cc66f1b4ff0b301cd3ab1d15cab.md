### Title
LRU Cache Thrashing via Unauthenticated Block Requests Causes Unbounded DB Query Amplification in `/block` Endpoint

### Summary
The `Block()` function in `rosetta/app/services/block_service.go` calls `updateOperationAccountAlias` for every operation in every returned transaction, which performs a synchronous database query (`GetAccountAlias`) on each LRU cache miss. Because the Rosetta API has no rate limiting and the LRU cache has a fixed capacity with no TTL, an unauthenticated attacker can cycle through blocks referencing more unique account IDs than the cache capacity (default 524,288), causing perpetual cache eviction and a proportional flood of database queries that degrades the `/block` endpoint.

### Finding Description
**Code path:**
- `block_service.go` `Block()` → line 69: `s.updateOperationAccountAlias(ctx, block.Transactions...)`
- `block_service.go` `updateOperationAccountAlias()` lines 115–122: for each operation, `s.entityCache.Get(accountId.GetId())` is checked; on miss, `s.accountRepo.GetAccountAlias(ctx, accountId)` executes a raw SQL query against the database, then `s.entityCache.Set(result.GetId(), result)` stores the result.

**Root cause:**
The LRU cache is initialized at line 34–37 with `lru.WithCapacity(entityCacheConfig.MaxSize)` (default `524288` per docs). There is no TTL, no per-IP rate limiting, and no request throttling anywhere in the middleware stack (`main.go` lines 217–219 only apply metrics and tracing middleware). The cache key space is the full set of account IDs that have ever appeared in blockchain transactions — on Hedera mainnet this is in the tens of millions, far exceeding the cache capacity.

**Exploit flow:**
1. Attacker identifies (or enumerates) a set of blocks whose combined unique account IDs exceed 524,288.
2. Attacker sends rapid, concurrent `POST /block` requests cycling through these blocks.
3. Each request causes `updateOperationAccountAlias` to iterate all operations; accounts not in cache trigger `GetAccountAlias` → synchronous DB query.
4. Because the working set exceeds cache capacity, LRU evicts entries inserted by prior requests, ensuring subsequent requests for the same blocks also miss the cache.
5. The result is O(operations_per_block × requests_per_second) database queries, sustained indefinitely.

**Why existing checks fail:**
- `maxTransactionsInBlock` (line 61–66) caps transactions per response but does not cap the number of unique account IDs per transaction or per operation.
- The LRU cache itself is the only protection, but it is the target of the attack — its fixed capacity is the exploitable constraint.
- No authentication, no rate limiting, no IP-based throttling exists in the rosetta middleware.

### Impact Explanation
Sustained cache thrashing causes the database connection pool (`maxOpenConnections` default: 100) to be saturated with `GetAccountAlias` queries. This degrades or blocks all `/block` endpoint responses for legitimate consumers (e.g., exchange integrations, block explorers relying on Rosetta). Because the mirror node's Rosetta API is the canonical interface for block/transaction data for Coinbase Rosetta-compatible systems, availability loss here directly impacts downstream transaction visibility and reconciliation pipelines.

### Likelihood Explanation
No privileges are required. The Rosetta API is publicly accessible on port 5700 with no authentication. Hedera mainnet has tens of millions of accounts distributed across millions of blocks, making it trivial to construct a cycling request set that exceeds the 524,288-entry cache. A single attacker with modest bandwidth can sustain the attack indefinitely using standard HTTP tooling. The attack is fully repeatable and stateless from the attacker's perspective.

### Recommendation
1. **Add per-IP or global rate limiting** on the `/block` endpoint in the middleware layer (e.g., using `golang.org/x/time/rate` or a reverse proxy like nginx/envoy in front of the service).
2. **Add a TTL to the LRU cache** so that entries expire and the cache naturally refreshes, reducing the value of thrashing. The `go-generics-cache` library supports TTL via `cache.WithTTL` on `Set` calls.
3. **Batch the `GetAccountAlias` lookups** within a single block request so that a single DB query can resolve multiple account IDs, reducing per-miss cost.
4. **Consider a bloom filter or negative cache** to avoid repeated DB queries for accounts with no alias (the common case), which currently still consume a DB round-trip and a cache slot.

### Proof of Concept
```bash
# Step 1: Identify two sets of blocks whose union of account IDs > 524288
# (On mainnet, any two non-overlapping ranges of ~300k blocks suffice)

# Step 2: Run concurrent cycling requests
for i in $(seq 1 1000000); do
  BLOCK_IDX=$(( (i % 600000) + 1 ))
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
         \"block_identifier\":{\"index\":$BLOCK_IDX}}" &
  # throttle goroutine count to avoid local exhaustion
  [ $((i % 50)) -eq 0 ] && wait
done
```

Expected result: database CPU and connection pool utilization spike to saturation; `/block` response latency increases from milliseconds to seconds or timeouts; legitimate requests begin receiving errors. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rosetta/app/services/block_service.go (L104-130)
```go
func (s *blockAPIService) updateOperationAccountAlias(
	ctx context.Context,
	transactions ...*types.Transaction,
) *rTypes.Error {
	for _, transaction := range transactions {
		operations := transaction.Operations
		for index := range operations {
			var cached types.AccountId
			var found bool

			accountId := operations[index].AccountId
			if cached, found = s.entityCache.Get(accountId.GetId()); !found {
				result, err := s.accountRepo.GetAccountAlias(ctx, accountId)
				if err != nil {
					return err
				}

				s.entityCache.Set(result.GetId(), result)
				cached = result
			}

			operations[index].AccountId = cached
		}
	}

	return nil
}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rosetta/app/persistence/account.go (L109-136)
```go
func (ar *accountRepository) GetAccountAlias(ctx context.Context, accountId types.AccountId) (
	zero types.AccountId,
	_ *rTypes.Error,
) {
	db, cancel := ar.dbClient.GetDbWithContext(ctx)
	defer cancel()

	var entity domain.Entity
	if err := db.Raw(selectCryptoEntityWithAliasById, sql.Named("id", accountId.GetId())).First(&entity).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return accountId, nil
		}

		return zero, hErrors.ErrDatabaseError
	}

	if len(entity.Alias) == 0 {
		return accountId, nil
	}

	accountAlias, err := types.NewAccountIdFromEntity(entity)
	if err != nil {
		log.Warnf("Failed to create AccountId from alias '0x%s': %v", hex.EncodeToString(entity.Alias), err)
		return accountId, nil
	}

	return accountAlias, nil
}
```
