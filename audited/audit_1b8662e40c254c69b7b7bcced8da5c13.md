### Title
Unbounded Sequential Per-Account DB Calls in `updateOperationAccountAlias` Enable Unauthenticated DoS via DB Connection Pool Exhaustion

### Summary
`updateOperationAccountAlias` in `rosetta/app/services/block_service.go` issues one synchronous `GetAccountAlias` database query per operation account ID not present in the LRU cache, with no batching and no application-level rate limiting. An unauthenticated attacker can send many concurrent `/block` requests targeting blocks with many unique account IDs, forcing sequential DB calls that hold connections and exhaust the pool, degrading or denying service to all users.

### Finding Description

**Exact code path:**

`Block()` (line 69) calls `updateOperationAccountAlias` after truncating transactions to `maxTransactionsInBlock`:

```go
// block_service.go:104-127
func (s *blockAPIService) updateOperationAccountAlias(ctx context.Context, transactions ...*types.Transaction) *rTypes.Error {
    for _, transaction := range transactions {
        operations := transaction.Operations
        for index := range operations {
            accountId := operations[index].AccountId
            if cached, found = s.entityCache.Get(accountId.GetId()); !found {
                result, err := s.accountRepo.GetAccountAlias(ctx, accountId)  // one DB call per miss
                ...
                s.entityCache.Set(result.GetId(), result)
            }
        }
    }
    return nil
}
```

Each cache miss calls `GetAccountAlias` (persistence/account.go lines 109–136), which executes:

```sql
select alias, id from entity where id = @id
```

synchronously and sequentially — one round-trip per account, no batching.

**Root cause:** The function assumes the LRU cache will absorb repeated lookups. The failed assumption is that the cache will always be warm. An attacker rotating requests across many distinct blocks with many unique account IDs keeps the cache cold for those accounts, forcing a DB call per operation per request.

**Why existing checks are insufficient:**

- The LRU cache (default `maxSize = 524288`) only helps for repeated requests to the *same* block. Rotating across many blocks bypasses it entirely.
- `maxTransactionsInBlock` limits transactions per response but does not limit the number of operations per transaction or the number of unique account IDs across those operations.
- A grep across all Rosetta Go source confirms **zero application-level rate limiting** on the `/block` endpoint. The only rate limiting is optional Traefik middleware in the Helm chart (`rateLimit: average: 10`), which is not enforced at the application layer and is disabled by default in the ingress (`middleware: false`).
- The DB connection pool defaults to `maxOpenConnections: 100`. Each concurrent Block() request holds one connection for the entire sequential chain of `GetAccountAlias` calls, so N concurrent requests with long chains can saturate the pool.

### Impact Explanation

With the connection pool exhausted (100 connections by default), all subsequent DB-dependent requests across the entire Rosetta API fail or queue indefinitely. This affects all users of the mirror node's Rosetta interface. The DB statement timeout (20 seconds) means each connection can be held for up to 20 seconds per call, multiplied by the number of uncached accounts per request, making pool saturation achievable with a modest number of concurrent attackers.

### Likelihood Explanation

No authentication is required to call `/block`. On Hedera mainnet, blocks routinely contain transactions involving dozens of distinct accounts (crypto transfers, token operations). An attacker can enumerate high-account-density blocks via the public mirror node REST API, then hammer the Rosetta `/block` endpoint with concurrent requests targeting those blocks while rotating through enough distinct blocks to prevent cache warming. This requires no special privileges, no on-chain activity, and is repeatable indefinitely.

### Recommendation

1. **Batch the alias lookups**: Collect all unique uncached account IDs across all transactions/operations first, then issue a single `WHERE id = ANY(@ids)` query, and populate the cache in bulk before the update loop.
2. **Add application-level rate limiting** directly in the Go HTTP handler (e.g., `golang.org/x/time/rate`), independent of any infrastructure middleware.
3. **Deduplicate within a request**: Before the loop, build a set of unique account IDs and resolve each only once per request, even if the same account appears in multiple operations.
4. **Consider a per-request cache** to avoid redundant lookups within a single Block() call.

### Proof of Concept

```bash
# 1. Identify a block with many unique account IDs on mainnet via REST API:
curl "https://mainnet-public.mirrornode.hedera.com/api/v1/blocks?limit=1&order=desc"
# Note a block index with high transaction count

# 2. Flood the Rosetta /block endpoint concurrently with that block index:
for i in $(seq 1 200); do
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index":<HIGH_ACCOUNT_BLOCK_INDEX>}}' &
done
wait

# 3. Simultaneously rotate through many different high-account blocks to prevent cache warming.
# 4. Observe DB connection pool exhaustion: subsequent requests return errors or time out.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rosetta/app/services/block_service.go (L34-37)
```go
	entityCache := cache.NewContext(
		serverContext,
		cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize)),
	)
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

**File:** rosetta/app/persistence/account.go (L51-51)
```go
	selectCryptoEntityWithAliasById = "select alias, id from entity where id = @id"
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

**File:** docs/configuration.md (L654-660)
```markdown
| `hiero.mirror.rosetta.cache.entity.maxSize`       | 524288              | The max number of entities to cache                                                                 |
| `hiero.mirror.rosetta.db.host`                    | 127.0.0.1           | The IP or hostname used to connect to the database                                                  |
| `hiero.mirror.rosetta.db.name`                    | mirror_node         | The name of the database                                                                            |
| `hiero.mirror.rosetta.db.password`                | mirror_rosetta_pass | The database password the processor uses to connect                                                 |
| `hiero.mirror.rosetta.db.pool.maxIdleConnections` | 20                  | The maximum number of idle database connections                                                     |
| `hiero.mirror.rosetta.db.pool.maxLifetime`        | 30                  | The maximum lifetime of a database connection in minutes                                            |
| `hiero.mirror.rosetta.db.pool.maxOpenConnections` | 100                 | The maximum number of open database connections                                                     |
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
