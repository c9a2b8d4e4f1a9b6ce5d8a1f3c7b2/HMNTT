### Title
LRU Cache Thrashing via Unbounded Token ID Cycling Causes Sustained DB Overload (Non-Network DoS)

### Summary
`tokenCache` in `rest/service/tokenService.js` is initialized with `quick-lru` using only `maxSize` (default 100,000) and no TTL/`maxAge`. An unauthenticated attacker can cycle requests through more than `maxSize` unique token IDs drawn from real on-chain account associations, continuously displacing legitimate tokens as the LRU victims, forcing every subsequent legitimate access to miss the cache and hit the database. With no rate limiting in the middleware stack and a DB connection pool capped at 10, this produces sustained database overload.

### Finding Description

**Exact code location**: `rest/service/tokenService.js`, lines 12–14 (cache construction) and lines 136–161 (`getCachedTokens`).

```js
// lines 12-14
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,   // default 100,000 — no maxAge/TTL
});
```

```js
// lines 136-161
async getCachedTokens(tokenIds) {
  const cachedTokens = new Map();
  const uncachedTokenIds = [];
  tokenIds.forEach((tokenId) => {
    const cachedToken = tokenCache.get(tokenId);   // LRU touch on hit
    if (cachedToken) {
      cachedTokens.set(tokenId, cachedToken);
    } else {
      uncachedTokenIds.push(tokenId);              // miss → DB
    }
  });
  if (uncachedTokenIds.length === 0) return cachedTokens;

  const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]); // DB query
  rows.forEach((row) => {
    tokenCache.set(row.token_id, new CachedToken(row));   // fills cache, evicts LRU
    ...
  });
  return cachedTokens;
}
```

**Root cause**: `quick-lru` evicts the *least recently used* entry when `maxSize` is exceeded. With no TTL, a token evicted by LRU pressure is gone from cache indefinitely until re-queried. The attacker exploits this by keeping a working set of `maxSize + N` unique token IDs in rotation: their tokens are always the most recently touched, so legitimate tokens become the LRU victims and are continuously evicted.

**Exploit flow**:
1. Attacker enumerates accounts on-chain that collectively hold associations to `>100,000` unique token IDs (feasible on Hedera mainnet, which has millions of tokens).
2. Attacker sends a high-rate stream of `GET /api/v1/accounts/{id}/tokens` requests, cycling through accounts whose token sets cover the `maxSize + N` superset.
3. Each request triggers `getTokenAccounts` → `getCachedTokens`. The attacker's token IDs are freshly touched (LRU-promoted), while legitimate tokens age out and are evicted.
4. Every legitimate user request for a previously-popular token now misses the cache and issues `tokenCacheQuery` (`WHERE token_id = ANY($1)`) against the database.
5. With the DB pool capped at 10 connections (`maxConnections: 10`, docs line 556), concurrent cache-miss DB queries from legitimate traffic saturate the pool, causing connection timeouts (20 s, docs line 555) and request failures.

**Why existing checks fail**:
- No `maxAge`/TTL on `tokenCache` — evicted entries are never automatically refreshed.
- No IP-based rate limiting anywhere in the middleware chain (`server.js` lines 67–98 shows only `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — no throttle).
- `authHandler` (`rest/middleware/authHandler.js`) only adjusts response *row limits* for authenticated users; it does not throttle unauthenticated request rates.
- The optional Redis response cache (`responseCacheCheckHandler`) is **disabled by default** (`cache.response.enabled: false`, docs line 549), so it provides no protection in default deployments.

### Impact Explanation
Sustained cache thrashing forces every legitimate token lookup to hit the database. With a pool of only 10 DB connections and a 20-second statement timeout, even moderate attacker throughput (tens of requests/second) can exhaust the pool, causing `connectionTimeout` errors for all REST API consumers. This is a non-network-based DoS: the attacker does not need to flood bandwidth — they only need to maintain a request rate sufficient to keep `>maxSize` unique token IDs cycling through the cache faster than the pool can recover. All endpoints that call `getTokenAccounts` (account token relationship queries) are affected.

### Likelihood Explanation
The attack requires no credentials and no special privileges — only HTTP access to the public REST API. On Hedera mainnet, millions of tokens exist and many accounts hold associations to thousands of tokens, making it straightforward to assemble a working set exceeding 100,000 unique token IDs. The attack is fully repeatable and self-sustaining: once the cache is in a thrashed state, each attacker request reinforces it. A single attacker with a modest script (e.g., 50 concurrent requests cycling through pre-enumerated account IDs) is sufficient to maintain the condition indefinitely.

### Recommendation
1. **Add `maxAge` (TTL) to `tokenCache`**: Initialize `quick-lru` with both `maxSize` and `maxAge` so evicted or stale entries are bounded in time, limiting the window of sustained miss amplification.
2. **Add IP-based rate limiting**: Introduce middleware (e.g., `express-rate-limit`) before route handlers to cap unauthenticated request rates per IP.
3. **Add a per-request token-ID batch size cap**: In `getCachedTokens`, limit `uncachedTokenIds.length` to a maximum (e.g., 25) per call to bound the per-request DB impact.
4. **Enable the Redis response cache by default**: The existing `responseCacheCheckHandler` with Redis would absorb repeated identical requests, but it is off by default.
5. **Consider a negative cache or bloom filter** for token IDs that do not exist, to avoid repeated DB hits for non-existent IDs.

### Proof of Concept

**Preconditions**:
- Public access to the mirror node REST API (no credentials needed).
- A pre-enumerated list of `>100,000` account IDs whose token associations collectively cover `>100,000` unique token IDs (obtainable by crawling `/api/v1/accounts` and `/api/v1/accounts/{id}/tokens`).

**Steps**:
```
# Step 1: Enumerate accounts and their token associations (one-time setup)
# Build a list: account_ids[] where union of their token sets > 100,000 unique token IDs

# Step 2: Launch rotating request flood (no auth required)
while true; do
  for account_id in "${ACCOUNT_IDS[@]}"; do
    curl -s "https://<mirror-node>/api/v1/accounts/${account_id}/tokens" &
  done
  wait
done
```

**Result**:
- `tokenCache` is continuously filled with the attacker's token IDs, evicting legitimate tokens as LRU victims.
- Legitimate users querying popular tokens always miss the cache.
- The 10-connection DB pool is saturated by cache-miss queries.
- Legitimate API requests begin timing out with `connectionTimeout` (20 s) errors, constituting a non-network DoS.

**Verification**: Monitor DB connection pool utilization and cache hit rate. Under attack, cache hit rate drops to near 0% for legitimate tokens and DB active connections stay pegged at `maxConnections`.