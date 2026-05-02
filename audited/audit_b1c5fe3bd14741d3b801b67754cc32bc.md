### Title
Unauthenticated Cache Eviction DoS via tokenCache LRU Flooding in `getTokenRelationships`

### Summary
The `tokenCache` quickLru instance in `rest/service/tokenService.js` is a single process-level, fixed-size LRU cache with a default `maxSize` of 100,000 entries. Any unauthenticated external user can continuously insert attacker-controlled token IDs into this cache by paginating through `/api/v1/accounts/{id}/tokens`, causing LRU eviction of legitimate cached tokens and forcing all subsequent legitimate requests to re-query the database for token metadata. The REST API has no rate limiting middleware, making this attack trivially repeatable.

### Finding Description
**Code locations:**
- Cache instantiation: `rest/service/tokenService.js` lines 12–14
- Cache write path: `rest/service/tokenService.js` lines 152–158 (`getCachedTokens`)
- Public endpoint handler: `rest/controllers/tokenController.js` lines 66–92 (`getTokenRelationships`)
- No rate limiting in REST server: `rest/server.js` lines 67–103 (only `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — no throttle middleware)

**Root cause:** The `tokenCache` is written to unconditionally for every uncached token ID returned by any call to `getTokenAccounts`. There is no per-IP, per-user, or global write-rate quota on cache insertions. The `authHandler` middleware (`rest/middleware/authHandler.js` lines 15–36) only sets a custom response `limit` for authenticated users; it does not block or throttle unauthenticated requests. The REST API has zero rate-limiting middleware (confirmed by `grep` across `rest/**/*.js` returning no hits for `rateLimit`/`throttle`).

**Exploit flow:**
1. Attacker identifies (or creates) accounts with many unique token associations on the Hedera network — these are publicly visible.
2. Attacker sends repeated `GET /api/v1/accounts/{id}/tokens?limit=100` requests, paginating via the `next` link, each inserting up to 100 unique token IDs into `tokenCache` via `tokenCache.set(tokenId, cachedToken)` at line 156.
3. After ~1,000 requests (100,000 / 100), the cache is full of attacker-controlled token IDs.
4. Attacker continues cycling through new unique token IDs, causing LRU eviction of legitimate entries.
5. Every legitimate request for a previously-cached token now misses the cache and falls through to `super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds])` at line 152, hitting the database.

**Why existing checks fail:**
- `authHandler` is optional (unauthenticated requests proceed normally, line 18–20 of `authHandler.js`: `if (!credentials) { return; }`)
- Response `limit` cap (max 100) only limits rows per response, not the number of requests or total cache writes
- `putTokenCache` (lines 121–129) checks `tokenCache.has(tokenId)` before writing, but this only prevents duplicate writes for the *same* token ID — it does not prevent flooding with *distinct* IDs
- The `quick-lru` library's LRU eviction is automatic and silent; there is no eviction callback or alerting

### Impact Explanation
The database connection pool is capped at **10 connections** with a **20-second statement timeout** (`rest/config.js`, `db.pool.maxConnections`). Under sustained cache-flooding, every legitimate token relationship request must execute an additional `SELECT ... FROM token WHERE token_id = any($1)` query. With enough concurrent attacker requests also consuming pool connections, legitimate requests queue behind the pool limit, causing latency spikes and eventual timeout errors (HTTP 500) for end users. This degrades the availability of the `/accounts/{id}/tokens` endpoint and any downstream consumer relying on it, without the attacker needing any credentials or special network position.

### Likelihood Explanation
The attack requires only an HTTP client and knowledge of any account with token associations (trivially discoverable via the public `/api/v1/tokens` endpoint). No authentication, no privileged access, no on-chain transactions are needed. The attack is fully repeatable and automatable with a simple script. The absence of any REST-layer rate limiting means there is no built-in defense to exhaust or bypass.

### Recommendation
1. **Add rate limiting to the REST API**: Introduce a per-IP request rate limiter (e.g., `express-rate-limit`) as middleware in `rest/server.js` before route registration, targeting at minimum the `/accounts/*/tokens` path.
2. **Bound cache write rate**: Track the number of new cache entries inserted per request and cap it (e.g., refuse to cache more than `limit` entries per single request invocation).
3. **Add TTL to tokenCache**: Instantiate `quickLru` with a `maxAge` option so stale attacker-inserted entries expire naturally, reducing the window of cache pollution.
4. **Consider a per-token-ID write cooldown**: In `getCachedTokens`, skip caching token IDs that were inserted within the last N seconds to reduce churn under flood conditions.

### Proof of Concept
```bash
# Step 1: Find an account with many token associations
ACCOUNT="0.0.12345"  # replace with any account having 100+ token associations

# Step 2: Flood the cache with unique token IDs via pagination
NEXT="/api/v1/accounts/${ACCOUNT}/tokens?limit=100&order=asc"
for i in $(seq 1 1100); do
  curl -s "https://<mirror-node-host>${NEXT}" -o /tmp/resp.json
  NEXT=$(jq -r '.links.next // empty' /tmp/resp.json)
  # Rotate to a different account when pagination exhausted
  [ -z "$NEXT" ] && NEXT="/api/v1/accounts/0.0.$((RANDOM+10000))/tokens?limit=100&order=asc"
done

# Step 3: Verify cache miss impact — legitimate requests now hit DB
# Monitor DB query rate; token metadata queries will spike proportionally
# to the number of legitimate requests after cache eviction
time curl "https://<mirror-node-host>/api/v1/accounts/0.0.98/tokens?limit=100"
# Response latency increases as DB is queried for every token ID
```