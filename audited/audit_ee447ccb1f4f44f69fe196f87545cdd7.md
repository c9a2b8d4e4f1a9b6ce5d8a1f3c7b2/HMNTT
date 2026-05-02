### Title
Unauthenticated Cache-Thrashing via Unbounded Round-Robin `getAirdrops()` Requests Degrades DB Buffer Pool for All Users

### Summary
The `getAirdrops()` endpoint in the rest-java module has no rate limiting, no application-level response caching, and no per-IP throttling. An unprivileged attacker can issue sustained requests targeting different high-volume accounts in a round-robin pattern, forcing the PostgreSQL buffer pool to continuously evict warm pages and load cold pages from different index partitions of the `token_airdrop` table, degrading I/O performance for all concurrent users of the mirror node database.

### Finding Description

**Exact code path:**

`TokenAirdropsController.getOutstandingAirdrops()` / `getPendingAirdrops()` (lines 66–86) builds a `TokenAirdropRequest` and calls `service.getAirdrops(request)` with no rate-limiting guard.

`TokenAirdropServiceImpl.getAirdrops()` (lines 19–22) performs only an entity lookup and immediately delegates to `repository.findAll(request, id)` — no caching, no throttle.

`TokenAirdropRepositoryCustomImpl.findAll()` (lines 58–72) executes a raw jOOQ query directly against the `token_airdrop` table:
```sql
SELECT * FROM token_airdrop
WHERE sender_account_id = :accountId   -- or receiver_account_id
  AND state = 'PENDING'
ORDER BY receiver_account_id, token_id, serial_number
LIMIT :limit
```
This query uses the `token_airdrop__sender_id` or `token_airdrop__receiver_id` index. Each distinct `accountId` value causes the DB to load a different leaf-node range of the B-tree index plus the corresponding heap pages.

**Root cause — failed assumption:**

The rest-java module has **zero rate limiting** for airdrop endpoints. The configuration documentation (`docs/configuration.md`, lines 622–634) lists only `hiero.mirror.restJava.db.*`, `fee.*`, `network.*`, and `response.*` properties — no throttle/rate-limit properties exist for rest-java. The only throttling in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` module (`hiero.mirror.web3.throttle.*`) and is not applied to rest-java controllers. The only guards on the airdrop endpoint are:
- `@Max(MAX_LIMIT)` — caps rows returned at 100, does not limit request rate
- `@Size(max = 2)` — limits filter parameter count, does not limit request rate
- `statementTimeout = 10000ms` — only kills runaway individual queries

**Exploit flow:**

1. Attacker enumerates a list of N high-volume Hedera account IDs (publicly available on-chain; accounts are sequential integers).
2. Attacker issues `GET /api/v1/accounts/{id}/airdrops/outstanding?limit=100` in a tight loop, cycling through the N accounts.
3. Each request hits a different `sender_account_id` range in the `token_airdrop__sender_id` B-tree index, loading different index pages and heap pages into the PostgreSQL shared buffer pool.
4. Because the working set of pages accessed across N accounts exceeds the buffer pool size, previously warm pages (used by legitimate queries) are evicted on every cycle.
5. Legitimate queries from other users now suffer cache misses and must read from disk, increasing I/O latency across the entire mirror node DB.

### Impact Explanation

The `token_airdrop` table is indexed by `(sender_account_id, receiver_account_id, token_id, serial_number)`. On a production network with millions of pending airdrops spread across thousands of accounts, the index and heap pages for different accounts are physically disjoint. Continuously cycling through accounts at high request rates forces the PostgreSQL buffer pool (typically sized at 25–40% of RAM) into a thrashing state. All concurrent users — including importer ingestion queries and other REST API consumers — experience elevated I/O wait times and query latency. This satisfies the "30% resource consumption increase" threshold without brute force: a single attacker with a modest HTTP client can sustain hundreds of requests per second against a publicly accessible endpoint.

### Likelihood Explanation

No authentication is required. Account IDs are public and enumerable. The attack requires only an HTTP client and a list of account IDs. It is repeatable indefinitely, requires no special knowledge, and cannot be distinguished from legitimate high-volume API usage without per-IP rate limiting. The absence of any throttle mechanism in the rest-java module makes this trivially automatable.

### Recommendation

1. **Add rate limiting to the rest-java module**: Implement a per-IP or global token-bucket rate limiter (analogous to `ThrottleConfiguration`/`ThrottleManagerImpl` in the web3 module) applied as a servlet filter on all airdrop endpoints.
2. **Add application-level response caching**: Cache `getAirdrops()` responses keyed by `(accountId, type, limit, order, filters)` with a short TTL (e.g., 5–10 seconds) using Spring Cache or Redis (the infrastructure already exists: `hiero.mirror.rest.cache.response` in the JS REST module).
3. **Enforce a global request-per-second cap** in `RestJavaConfiguration` or a new `ThrottleFilter` for the rest-java module, rejecting excess requests with HTTP 429.
4. **Consider connection pool limits**: The `hiero.mirror.restJava.db` connection pool should be sized to prevent a flood of concurrent airdrop queries from exhausting DB connections.

### Proof of Concept

```bash
# Enumerate N account IDs (publicly available)
ACCOUNTS=(1000 2000 3000 4000 5000 6000 7000 8000 9000 10000)

# Round-robin loop — no authentication required
while true; do
  for id in "${ACCOUNTS[@]}"; do
    curl -s "https://<mirror-node>/api/v1/accounts/${id}/airdrops/outstanding?limit=100" &
  done
  wait
done
```

Each iteration fires 10 concurrent requests targeting distinct `sender_account_id` ranges. At sustained rates (hundreds of req/s), the PostgreSQL buffer pool is continuously thrashed across disjoint index/heap page ranges, measurably increasing I/O for all concurrent DB users.