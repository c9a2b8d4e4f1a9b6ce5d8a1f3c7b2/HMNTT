### Title
Unbounded Cache Thrashing via Cyclic Block Requests in `updateOperationAccountAlias`

### Summary
The `updateOperationAccountAlias` function in `rosetta/app/services/block_service.go` uses a process-local LRU cache (default capacity 524,288) to avoid repeated DB lookups for account aliases. Because the Rosetta `/block` and `/block/transaction` endpoints are unauthenticated and have no rate limiting, an unprivileged attacker can cycle requests across blocks whose operations collectively reference more unique account IDs than the cache capacity, causing a sustained 100% cache-miss rate and a DB query for every single operation in every request.

### Finding Description

**Exact code path:**

`rosetta/app/services/block_service.go`, lines 104–130 (`updateOperationAccountAlias`):

```go
if cached, found = s.entityCache.Get(accountId.GetId()); !found {
    result, err := s.accountRepo.GetAccountAlias(ctx, accountId)   // DB hit
    ...
    s.entityCache.Set(result.GetId(), result)
}
```

The cache is an LRU with capacity `entityCacheConfig.MaxSize` (default **524,288**, per `docs/configuration.md` line 654: `hiero.mirror.rosetta.cache.entity.maxSize = 524288`).

**Root cause / failed assumption:**

The design assumes the working set of account IDs seen across requests will fit within the cache. This assumption fails when an attacker deliberately cycles through blocks whose operations span more than 524,288 distinct account IDs — a realistic condition on mainnet, which has millions of accounts.

**Exploit flow:**

1. Attacker enumerates (or guesses) a set of block indices whose transactions collectively reference N > 524,288 unique account IDs.
2. Attacker sends a continuous stream of `POST /block` requests cycling through those block indices.
3. Each request calls `updateOperationAccountAlias` for every operation in the block.
4. Because the LRU is always full of "wrong" entries (evicted by the previous request's IDs), every `entityCache.Get` returns `found = false`.
5. Every miss triggers `accountRepo.GetAccountAlias` → `db.Raw("select alias, id from entity where id = @id", ...)` (account.go line 117).
6. With `maxOpenConnections = 100` (docs line 660), the DB connection pool is saturated, degrading all other consumers.

**Why existing checks are insufficient:**

- The LRU cache itself is the only defense; there is no rate limiting, no per-IP throttling, and no authentication on the Rosetta API (grep for `rateLimit|throttle` in `rosetta/**/*.go` returns zero matches).
- `maxTransactionsInBlock` limits transactions per response but does not limit the number of operations per transaction or the number of concurrent requests.
- The DB query (`selectCryptoEntityWithAliasById`) is a primary-key lookup and will succeed quickly per query, meaning the attacker can sustain a high query rate without triggering timeouts.

### Impact Explanation

Every cache miss issues a synchronous DB query. With no rate limiting and a public endpoint, an attacker can drive the DB connection pool (`maxOpenConnections = 100`) to saturation, causing query queuing and latency spikes for all other Rosetta API consumers and any other service sharing the same DB. This is a griefing/availability impact with no economic cost to the attacker.

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond public block indices, and no on-chain activity. On mainnet, millions of accounts exist across historical blocks, making it trivial to identify a cycling set of blocks that exceeds the 524,288-entry cache. The attack is fully repeatable and can be automated with a simple HTTP client loop.

### Recommendation

1. **Add per-IP or global rate limiting** to the Rosetta HTTP server (e.g., via middleware using `golang.org/x/time/rate`) to bound the number of `/block` and `/block/transaction` requests per second.
2. **Add a negative/tombstone cache entry** for accounts with no alias so repeated lookups for the same non-aliased account do not re-query the DB.
3. **Consider a request-scoped deduplication map** inside `updateOperationAccountAlias` so that within a single block response, the same account ID is only looked up once even on a cold cache.
4. **Expose cache hit-rate metrics** and alert on sustained low hit rates as an operational signal for this attack pattern.

### Proof of Concept

```python
import requests, itertools, threading

ROSETTA = "http://<rosetta-host>:5700"

# Pre-identify block indices whose operations span many unique accounts.
# On mainnet, any high-activity block range works.
BLOCKS = list(range(1, 600_000))  # adjust to known high-activity range

def spam():
    for idx in itertools.cycle(BLOCKS):
        requests.post(f"{ROSETTA}/block",
                      json={"network_identifier": {"blockchain":"Hedera","network":"mainnet"},
                            "block_identifier": {"index": idx}},
                      timeout=10)

# Launch concurrent workers to saturate DB connection pool
threads = [threading.Thread(target=spam) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

Each iteration cycles through blocks referencing distinct account IDs, ensuring the LRU cache is continuously evicted and every operation triggers a `select alias, id from entity where id = ?` query, saturating the 100-connection DB pool.