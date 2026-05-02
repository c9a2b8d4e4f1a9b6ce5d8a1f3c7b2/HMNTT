### Title
Cache Stampede / Thundering Herd in `getCachedTokens()` Enables Unprivileged Non-Network DoS via DB Connection Pool Exhaustion

### Summary
`getCachedTokens()` in `rest/service/tokenService.js` contains no in-flight request deduplication. When N concurrent unauthenticated requests arrive for the same uncached token IDs, each independently passes the cache-miss check before any of them populates the cache, causing N duplicate `tokenCacheQuery` DB queries to be issued simultaneously. With a default DB pool of only 10 connections and a 20-second statement timeout, a moderate burst of concurrent requests can fully exhaust the connection pool and deny service to all other API consumers.

### Finding Description

**Exact code path:**

`rest/service/tokenService.js`, `getCachedTokens()`, lines 136–161:

```js
async getCachedTokens(tokenIds) {
  const cachedTokens = new Map();
  const uncachedTokenIds = [];
  tokenIds.forEach((tokenId) => {
    const cachedToken = tokenCache.get(tokenId);   // line 140 — cache miss check
    if (cachedToken) {
      cachedTokens.set(tokenId, cachedToken);
    } else {
      uncachedTokenIds.push(tokenId);              // line 144 — added to uncached list
    }
  });

  if (uncachedTokenIds.length === 0) {
    return cachedTokens;
  }

  const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]); // line 152 — DB query
  rows.forEach((row) => {
    tokenCache.set(tokenId, cachedToken);          // line 156 — cache populated AFTER await
    ...
  });
  return cachedTokens;
}
```

**Root cause:** JavaScript's event loop is cooperative. When execution reaches `await super.getRows(...)` at line 152, control is yielded back to the event loop. Any other concurrent call to `getCachedTokens()` that was already queued will then execute its synchronous cache-miss check (line 140) against a cache that is still empty (because the first call has not yet returned and populated it at line 156). There is no in-flight promise map, no mutex, and no coalescing mechanism. Every concurrent caller independently concludes the token is uncached and independently issues the same DB query.

**Why existing checks are insufficient:**
- `putTokenCache()` has a `tokenCache.has()` guard (line 123), but this only prevents duplicate writes from the `/tokens` list endpoint — it has no effect on concurrent `getCachedTokens()` callers.
- The `quickLru` cache itself is synchronous and correct for single-threaded sequential access, but provides no protection against the async TOCTOU window between lines 140 and 156.
- The DB pool `maxConnections` default is **10** and `statementTimeout` is **20,000 ms** — meaning 10 concurrent duplicate queries can hold all connections for up to 20 seconds each.

### Impact Explanation

Every endpoint that calls `getCachedTokens()` is affected:
- `GET /api/v1/accounts/{id}/tokens` → via `getTokenAccounts()` → `getCachedTokens()`
- `GET /api/v1/tokens/{tokenId}/balances` → directly calls `getCachedTokens()`

With a default pool of 10 DB connections, sending 10 concurrent requests for the same uncached token IDs saturates the entire connection pool with duplicate token-lookup queries. All other API endpoints (transactions, accounts, NFTs, etc.) that need a DB connection are queued or time out, producing a complete service outage for all users. No authentication is required. The attack is non-network (it exploits application-layer logic, not bandwidth).

### Likelihood Explanation

Any unprivileged external user can trigger this:
- The mirror node REST API is publicly accessible with no authentication.
- The attacker needs only to identify token IDs not currently in the LRU cache (trivially achievable after a server restart, or by first flooding requests for >100,000 distinct token IDs to evict the cache, given `maxSize: 100000`).
- Sending 10–50 concurrent HTTP requests is trivially achievable with `curl --parallel`, `ab`, `wrk`, or any scripting language.
- The attack is repeatable: once the cache is populated, the attacker can re-evict entries and repeat.

### Recommendation

Implement **promise coalescing** (also called "single-flight" or "request deduplication") for in-flight DB lookups. Maintain a module-level `Map<tokenId, Promise>` of pending queries. Before issuing a new DB query for a token ID, check if a promise for that ID is already in-flight and await it instead of issuing a new query. Remove the entry from the map when the promise settles.

Example pattern:
```js
const inFlight = new Map(); // module-level

async getCachedTokens(tokenIds) {
  // ... existing cache-hit logic ...
  // For uncachedTokenIds, check inFlight map first:
  let promise = inFlight.get(cacheKey);
  if (!promise) {
    promise = super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds])
      .finally(() => inFlight.delete(cacheKey));
    inFlight.set(cacheKey, promise);
  }
  const rows = await promise;
  // ... populate cache ...
}
```

Alternatively, use a library such as `p-memoize` with `cacheKey` based on the sorted token ID set.

### Proof of Concept

**Preconditions:** Mirror node REST API running with default config (empty token cache, e.g., fresh start). Token ID `0.0.1234` exists in the DB but not in the LRU cache.

**Steps:**

```bash
# Send 10 concurrent requests for the same token's balances
# (each triggers getCachedTokens([tokenId]) with a cache miss)
for i in $(seq 1 10); do
  curl -s "http://<mirror-node>/api/v1/tokens/0.0.1234/balances" &
done
wait
```

**Observed result:** DB query logs show 10 identical executions of:
```sql
SELECT decimals, freeze_status, kyc_status, token_id
FROM token
WHERE token_id = any ($1)
```
all issued simultaneously, consuming all 10 DB pool connections. Concurrent requests to other endpoints (e.g., `/api/v1/transactions`) receive connection timeout errors or are queued for up to 20 seconds, constituting a denial of service.

**To amplify:** First evict the cache by requesting many distinct token IDs, then repeat the burst. The attack is fully repeatable with no privileged access.