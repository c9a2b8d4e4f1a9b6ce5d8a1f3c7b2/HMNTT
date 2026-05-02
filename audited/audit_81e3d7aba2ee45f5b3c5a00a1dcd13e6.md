### Title
Unauthenticated DB Connection Pool Exhaustion via Double Sequential Query in `getTokenAccounts()`

### Summary
`getTokenAccounts()` in `rest/service/tokenService.js` issues two sequential `getRows()` calls per request — one for token relationships and one for uncached token metadata — each holding a connection from the 10-connection pool for the duration of the query. With no rate limiting on the REST API's `/accounts/:idOrAliasOrEvmAddress/tokens` endpoint and a default pool cap of 10 connections, an unprivileged attacker sending ≥10 concurrent requests against accounts with many uncached token associations can saturate the pool, causing all subsequent REST API database operations to queue and time out, effectively taking down the mirror node REST API.

### Finding Description

**Code path:**

`rest/controllers/tokenController.js` `getTokenRelationships()` (line 74) calls `TokenService.getTokenAccounts(query)`.

Inside `getTokenAccounts()` (`rest/service/tokenService.js` lines 96–115):
- **Line 98**: `const rows = await super.getRows(sqlQuery, params);` — acquires a pool connection, runs the `token_account` join query, releases the connection.
- **Line 104**: `const cachedTokens = await this.getCachedTokens(tokenIds);` — for any token IDs not in the in-process LRU cache, `getCachedTokens()` at **line 152** issues `await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds])` — acquires a second pool connection, runs the `token` table query, releases it.

`getRows()` in `rest/service/baseService.js` line 55–57 delegates to `pool.queryQuietly()`. In `rest/utils.js` lines 1518–1521, when no `preQueryHint` is set (the case here), it calls `this.query(query, params)` — the `node-postgres` pool's built-in method, which acquires a client, executes the query, and releases it only after the query completes. Each `await` holds a connection for the full query duration.

**Root cause:** Two sequential `await getRows()` calls per request, each occupying a pool slot for the full query execution time, combined with:
- Pool hard cap of **10 connections** (`rest/dbpool.js` line 14, default from `docs/configuration.md` line 556: `hiero.mirror.rest.db.pool.maxConnections = 10`)
- Connection timeout of **20 seconds** (`connectionTimeoutMillis`, line 13 of `dbpool.js`)
- **Zero rate limiting** on the Node.js REST API for this endpoint (the `ThrottleConfiguration`/`ThrottleManagerImpl` throttle exists only in the `web3` Java module, not in the REST API)

**Failed assumption:** The design assumes the in-process `quickLru` token cache (`tokenCache`, line 12 of `tokenService.js`) will absorb most repeat lookups. However, the cache is per-process and per-instance, is cold on startup or after eviction (`maxSize: config.cache.token.maxSize`), and an attacker can trivially target accounts whose token associations reference token IDs not yet cached.

### Impact Explanation

With 10 concurrent requests each holding a connection for the duration of a slow `token_account` query (accounts with hundreds of associations produce large result sets), the pool is fully saturated. The 11th and subsequent requests block waiting for a free connection for up to 20 seconds, then fail. Because the global `pool` object (`rest/dbpool.js` line 36) is shared across all REST API endpoints, pool exhaustion on `/accounts/:id/tokens` starves every other endpoint — `/transactions`, `/contracts`, `/balances`, etc. — of database connections simultaneously. This constitutes a full REST API denial of service, matching the "total network shutdown" severity classification for the mirror node's read path.

### Likelihood Explanation

No authentication, API key, or IP-based rate limit is required. Any internet-accessible mirror node deployment is vulnerable. The attack requires only a standard HTTP client capable of issuing concurrent requests (e.g., `curl`, `ab`, `wrk`). The attacker needs only one valid account ID with many token associations (easily discoverable via the public `/accounts` endpoint). The attack is repeatable and sustainable: as long as the attacker maintains ≥10 concurrent in-flight requests, the pool remains exhausted. The 20-second `connectionTimeout` means each attacker request ties up a slot for up to 20 seconds even if the query is slow, amplifying the effect.

### Recommendation

1. **Add concurrency/rate limiting to the REST API**: Implement a per-IP or global request rate limiter (e.g., `express-rate-limit`) on the Node.js REST server, mirroring the `ThrottleManagerImpl` pattern used in the web3 module.
2. **Increase pool size or add a request queue cap**: Raise `hiero.mirror.rest.db.pool.maxConnections` and add an application-level concurrency semaphore to bound the number of simultaneous in-flight DB operations.
3. **Merge the two queries into one**: Rewrite `getTokenAccounts()` to JOIN the `token` table directly in `tokenRelationshipsQuery` instead of issuing a separate `tokenCacheQuery`, eliminating the second connection acquisition entirely.
4. **Add a statement timeout guard**: The existing `statement_timeout` (20 s) helps but does not prevent pool exhaustion from many concurrent slow queries; a shorter timeout (e.g., 5 s) combined with rate limiting would reduce the attack window.

### Proof of Concept

**Preconditions:**
- Mirror node REST API running with default config (`maxConnections=10`)
- At least one account (e.g., `0.0.12345`) with many token associations whose token IDs are not yet in the LRU cache (cold start or after cache eviction)

**Steps:**
```bash
# Send 15 concurrent requests to saturate the 10-connection pool
for i in $(seq 1 15); do
  curl -s "http://<mirror-node>:5551/api/v1/accounts/0.0.12345/tokens?limit=100" &
done
wait

# Immediately probe a different endpoint — it will time out or return 500
curl -v "http://<mirror-node>:5551/api/v1/transactions?limit=1"
```

**Expected result:** The transactions request (and all other REST API requests) hangs for up to 20 seconds then fails with a DB connection timeout error, as all 10 pool connections are held by the concurrent `getTokenAccounts()` calls. The REST API is effectively unavailable for the duration of the attack.