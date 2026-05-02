### Title
Concurrent `/block` Requests Cause Unbounded DB Query Multiplication via Missing Request Coalescing and Non-Atomic Cache Check-Then-Set

### Summary
The `Block()` handler in `rosetta/app/services/block_service.go` performs no request deduplication or coalescing. Every concurrent request for the same block independently executes `FindBetween()` (which issues multiple batched DB queries with no caching) and `updateOperationAccountAlias()` (which has a non-atomic check-then-set against an LRU cache). An unprivileged attacker sending N concurrent requests for a high-transaction block multiplies DB query load by N, easily exceeding 30% above baseline resource consumption.

### Finding Description

**Code path:**

`Block()` at `rosetta/app/services/block_service.go` lines 47–74:
- Line 56: `s.FindBetween(ctx, block.ConsensusStartNanos, block.ConsensusEndNanos)` — delegates directly to `transactionRepository.FindBetween()` with no caching layer.
- Line 69: `s.updateOperationAccountAlias(ctx, block.Transactions...)` — iterates all operations and performs a non-atomic cache check-then-set.

`FindBetween()` at `rosetta/app/persistence/transaction.go` lines 112–171:
- Issues `ceil(N / 2000)` sequential DB queries per request (batchSize = 2000, line 22). For a block with 10,000 transactions, this is 5 DB queries per request. With 20 concurrent requests, that is 100 identical DB queries for the same data.
- There is no result cache at any layer between the HTTP handler and the database.

`updateOperationAccountAlias()` at `rosetta/app/services/block_service.go` lines 104–129:
```go
if cached, found = s.entityCache.Get(accountId.GetId()); !found {
    result, err := s.accountRepo.GetAccountAlias(ctx, accountId)  // DB query
    s.entityCache.Set(result.GetId(), result)
    cached = result
}
```
The `Get` and `Set` on the LRU cache are individually thread-safe, but the check-then-set is not atomic. Multiple goroutines concurrently processing the same block will all observe `found = false` for the same uncached account IDs and all issue `GetAccountAlias()` DB queries (each executing `selectCryptoEntityWithAliasById` at `rosetta/app/persistence/account.go` line 51).

**Root cause:** The `Block()` handler has no singleflight/request-coalescing mechanism, no response cache for block data, and a racy check-then-set in the account alias cache. The failed assumption is that the LRU cache prevents redundant DB queries under concurrent load — it does not, because the critical section between `Get` and `Set` is unguarded.

**Why existing checks fail:**

The Traefik middleware (`charts/hedera-mirror-rosetta/values.yaml` lines 149–166) defines `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per host, but:
1. `global.middleware` defaults to `false` (line 95), so this middleware is **not deployed by default**.
2. The application itself (`rosetta/main.go` lines 217–219) only applies `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — no rate limiting.
3. Even when enabled, per-IP limits are trivially bypassed with multiple source IPs (cloud VMs, proxies).

### Impact Explanation
For a block with T transactions and U unique accounts, C concurrent requests generate:
- `C × ceil(T / 2000)` transaction DB queries (no caching in `FindBetween`)
- Up to `C × U` account alias DB queries (cache stampede in `updateOperationAccountAlias`)
- `C × T` in-memory transaction objects allocated simultaneously

At C=20 concurrent requests against a block with 10,000 transactions and 500 unique accounts: 100 transaction batch queries + up to 10,000 account alias queries + 200,000 transaction object allocations. This is a linear amplification of DB and memory load achievable with no privileges, easily exceeding 30% above baseline.

### Likelihood Explanation
The `/block` endpoint is a standard, unauthenticated Rosetta API endpoint. High-transaction blocks on Hedera are publicly identifiable via the mirror node REST API. An attacker needs only an HTTP client and knowledge of a block index or hash. The attack is trivially repeatable, requires no special tooling, and is effective even from a single machine using async HTTP clients (e.g., `curl`, `wrk`, `hey`). The default deployment has no application-level rate limiting.

### Recommendation
1. **Apply `golang.org/x/sync/singleflight`** in `Block()` keyed on the block identifier, so concurrent requests for the same block share a single `FindBetween()` + `updateOperationAccountAlias()` execution.
2. **Add a short-lived response cache** (e.g., 5–10 seconds) for completed block responses, keyed on block hash/index.
3. **Make the account alias cache check-then-set atomic** using a `sync.Mutex` or `sync.Map` with a `LoadOrStore` pattern to prevent cache stampede.
4. **Enable the Traefik middleware by default** (`global.middleware: true`) or implement application-level rate limiting in the Go HTTP server.

### Proof of Concept
```bash
# 1. Identify a high-transaction block (public info)
BLOCK_INDEX=<high_tx_block_index>

# 2. Send 50 concurrent POST requests to /block for the same block
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>/block \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},\"block_identifier\":{\"index\":$BLOCK_INDEX}}" &
done
wait

# 3. Observe DB query count spike in pg_stat_activity or slow query logs:
#    Expected: 50 × ceil(T/2000) transaction queries + up to 50 × U account alias queries
#    vs. baseline of 1 × ceil(T/2000) + U queries for a single request
```
The DB query count and memory allocation metrics will show a linear increase proportional to the number of concurrent requests, with no deduplication occurring at any layer.