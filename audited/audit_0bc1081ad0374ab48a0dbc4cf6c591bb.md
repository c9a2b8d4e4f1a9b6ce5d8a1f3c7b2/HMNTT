### Title
Unbounded Cache Thrashing via Cyclic Block Requests Forcing Per-Operation DB Queries in `updateOperationAccountAlias()`

### Summary
The `updateOperationAccountAlias()` function in `rosetta/app/services/block_service.go` performs a synchronous `GetAccountAlias()` database query for every operation whose `AccountId` is not found in the process-level LRU `entityCache`. Because the Rosetta `/block` and `/block/transaction` endpoints have no application-level rate limiting, an unprivileged attacker can continuously request blocks whose combined operations reference more unique `AccountId` values than the LRU cache's `MaxSize` (default 524,288), sustaining a 100% cache miss rate and forcing a DB query for every single operation across all transactions in every request.

### Finding Description

**Code path:**

`rosetta/app/services/block_service.go` — `NewBlockAPIService()` (lines 34–37) initializes a pure LRU cache with no TTL:
```go
entityCache := cache.NewContext(
    serverContext,
    cache.AsLRU[int64, types.AccountId](lru.WithCapacity(entityCacheConfig.MaxSize)),
)
```
Default `MaxSize` is 524,288 (`hiero.mirror.rosetta.cache.entity.maxSize`).

`updateOperationAccountAlias()` (lines 104–130) iterates every operation of every transaction and on cache miss calls `s.accountRepo.GetAccountAlias(ctx, accountId)` — a synchronous SQL query (`select alias, id from entity where id = @id`) — then stores the result:
```go
if cached, found = s.entityCache.Get(accountId.GetId()); !found {
    result, err := s.accountRepo.GetAccountAlias(ctx, accountId)
    ...
    s.entityCache.Set(result.GetId(), result)
}
```

**Root cause:** The LRU cache is eviction-only (no TTL). An attacker who cycles requests across blocks whose union of operation `AccountId` values exceeds `MaxSize` will continuously evict warm entries before they can be reused, producing a sustained 100% miss rate. There is no application-level rate limiting on the Rosetta block endpoints — the `main.go` router (`rosetta/main.go` lines 111–119) applies only CORS and metrics middleware; no throttle middleware exists for the block service.

**Failed assumption:** The design assumes the working set of active account IDs fits within the LRU capacity. On Hedera mainnet (tens of millions of accounts), an attacker can trivially identify blocks with many unique participants and cycle through them.

### Impact Explanation

Each cache miss issues a synchronous DB query against the `entity` table. The DB connection pool defaults to `maxOpenConnections: 100`. An attacker cycling through N > 524,288 unique account IDs across a sequence of block requests will:
- Saturate the DB connection pool with alias-lookup queries
- Starve legitimate queries (balance lookups, transaction fetches) of connections
- Increase DB CPU and I/O proportionally to the miss rate × operations-per-block × request rate

With the Traefik `inFlightReq: 5` per IP and `rateLimit: average: 10` per host (both optional, deployment-specific), an attacker at 10 req/s with blocks containing hundreds of operations each can generate thousands of DB queries per second that would otherwise be served from cache.

### Likelihood Explanation

- **No authentication required** — the Rosetta API is a public read endpoint by design
- **No application-level rate limiting** — unlike the web3 API (`ThrottleManagerImpl`), the Rosetta block service has zero in-process throttling
- **Block contents are public** — an attacker can pre-scan the chain to identify blocks with the highest unique-account density
- **Traefik middleware is optional** — it is only active when `global.middleware` and `middleware` are both set in the Helm values; direct deployments or non-Kubernetes deployments have no protection
- **Repeatable indefinitely** — the attack requires no state, credentials, or special network position; any HTTP client suffices

### Recommendation

1. **Add application-level rate limiting** to the Rosetta block endpoints (analogous to `ThrottleManagerImpl` in the web3 module), enforced inside the Go server, not relying solely on infrastructure middleware.
2. **Add per-request deduplication** in `updateOperationAccountAlias()`: collect all unique `AccountId` values from all operations before querying, so a single block request with repeated accounts only issues one DB query per unique ID.
3. **Add a TTL** to the `entityCache` (the `go-generics-cache` library supports `cache.WithExpiration`) so stale entries are not held indefinitely and the cache naturally refreshes.
4. **Enforce a maximum operations-per-request budget** to bound the number of DB queries any single block request can trigger.

### Proof of Concept

**Preconditions:** Rosetta node running in online mode, accessible without authentication, Traefik middleware not deployed (or bypassed by direct access to port 5700).

**Steps:**

1. Identify two or more blocks on mainnet/testnet whose combined set of unique operation account IDs exceeds 524,288 (trivially achievable by selecting high-activity blocks spanning many accounts).

2. Send requests in a tight loop cycling through those blocks:
```bash
while true; do
  # Block A — contains accounts 1..300000
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index": <block_A_index>}}'

  # Block B — contains accounts 300001..600000 (evicts all of Block A's entries)
  curl -s -X POST http://<rosetta-host>:5700/block \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index": <block_B_index>}}'
done
```

3. **Result:** Every request processes operations whose account IDs were evicted by the previous request. `GetAccountAlias()` is called for every operation on every request. DB connection pool utilization climbs to saturation; legitimate node queries experience increased latency or connection timeouts, increasing node resource consumption by well over 30% compared to the cache-warm baseline.