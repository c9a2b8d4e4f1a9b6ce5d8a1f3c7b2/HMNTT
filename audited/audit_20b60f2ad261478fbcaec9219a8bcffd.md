### Title
Thundering Herd / Cache Stampede in `getCachedTokens()` via Concurrent Requests for Uncached Token IDs

### Summary
`getCachedTokens()` in `rest/service/tokenService.js` checks the in-memory `tokenCache` synchronously, then issues an async DB query for any uncached token IDs. Because the cache is only populated *after* the `await` resolves, any number of concurrent requests that arrive before the first query completes will each independently find the cache empty and each issue their own redundant DB query. There is no in-flight promise deduplication or coalescing mechanism anywhere in the code path.

### Finding Description
**Exact location:** `rest/service/tokenService.js`, `getCachedTokens()`, lines 136–161.

```
136  async getCachedTokens(tokenIds) {
137    const cachedTokens = new Map();
138    const uncachedTokenIds = [];
139    tokenIds.forEach((tokenId) => {
140      const cachedToken = tokenCache.get(tokenId);   // ← synchronous check
141      if (cachedToken) {
142        cachedTokens.set(tokenId, cachedToken);
143      } else {
144        uncachedTokenIds.push(tokenId);              // ← cache miss
145      }
146    });
148    if (uncachedTokenIds.length === 0) { return cachedTokens; }
152    const rows = await super.getRows(               // ← async DB call; suspends here
              TokenService.tokenCacheQuery, [uncachedTokenIds]);
153    rows.forEach((row) => {
156      tokenCache.set(tokenId, cachedToken);         // ← cache populated ONLY after await
157      ...
158    });
```

**Root cause:** The cache check (line 140) and the cache write (line 156) are separated by an `await` boundary (line 152). Node.js's event loop is free to schedule other coroutines during that suspension. Any concurrent call to `getCachedTokens()` with the same token IDs will pass the cache-miss check (line 140) before the first call's `await` resolves and populates the cache, causing it to also reach line 152 and issue its own DB query.

**Failed assumption:** The code assumes that once a DB query is in-flight, subsequent callers will find the result in `tokenCache`. This is false — `tokenCache` stores only completed results, not pending promises.

**No existing mitigation:** `BaseService.getRows()` is a plain `pool.queryQuietly()` wrapper with no deduplication. There is no separate "in-flight" map, no mutex, and no promise-coalescing layer anywhere in the token cache path.

### Impact Explanation
Every concurrent request for the same set of uncached token IDs results in a separate `SELECT … FROM token WHERE token_id = ANY($1)` query against the database. Under sustained concurrent load (e.g., a burst of requests for a newly-listed token), this multiplies DB query volume linearly with the number of concurrent requests. This degrades DB performance for all users of the mirror node, potentially causing query timeouts or connection pool exhaustion. The impact is limited to performance/availability (no data corruption, no economic loss), consistent with the "griefing with no economic damage" severity classification.

### Likelihood Explanation
Any unauthenticated user can trigger this by sending N concurrent HTTP requests to any endpoint that calls `getCachedTokens()` (e.g., `GET /api/v1/tokens/:tokenId/balances` at line 726 of `rest/tokens.js`, or `getTokenAccounts()` at line 104 of `tokenService.js`). No special privileges, credentials, or knowledge of internals are required. The attack is trivially repeatable: the cache window is only as long as the DB query latency, so a sustained stream of concurrent requests keeps the stampede alive indefinitely.

### Recommendation
Introduce **promise coalescing** (also called a "single-flight" or "request deduplication" pattern): store the in-flight `Promise` for a given set of token IDs in a secondary `Map<tokenId, Promise>` before issuing the DB query. Subsequent callers that find a token ID in the in-flight map should `await` the existing promise rather than issuing a new query. After the promise resolves and the cache is populated, remove the entry from the in-flight map. Example sketch:

```js
const inFlight = new Map(); // tokenId → Promise<CachedToken>

// For each uncached token ID, reuse or create an in-flight promise
for (const tokenId of uncachedTokenIds) {
  if (!inFlight.has(tokenId)) {
    const p = fetchFromDb([tokenId]).then(result => {
      tokenCache.set(tokenId, result);
      inFlight.delete(tokenId);
      return result;
    });
    inFlight.set(tokenId, p);
  }
  cachedTokens.set(tokenId, await inFlight.get(tokenId));
}
```

Alternatively, batch all uncached IDs into a single coalesced promise keyed on the sorted ID set.

### Proof of Concept
**Preconditions:** Mirror node REST API is running; token IDs `300`, `400`, `500` are not yet in `tokenCache` (e.g., after a server restart or cache eviction).

**Steps:**
1. Send 50 concurrent HTTP requests simultaneously:
   ```
   for i in $(seq 1 50); do
     curl -s "http://localhost:5551/api/v1/tokens/0.0.300/balances" &
   done
   wait
   ```
2. Monitor the database query log (e.g., `pg_stat_activity` or `log_min_duration_statement = 0`).

**Expected (vulnerable) result:** Up to 50 identical `SELECT decimals, freeze_status, kyc_status, token_id FROM token WHERE token_id = ANY('{300}')` queries appear in the DB log simultaneously — one per concurrent request — before any of them has had a chance to populate `tokenCache`.

**Expected (fixed) result:** Exactly 1 DB query is issued; all other concurrent callers await the same in-flight promise. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L136-161)
```javascript
  async getCachedTokens(tokenIds) {
    const cachedTokens = new Map();
    const uncachedTokenIds = [];
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
    });

    if (uncachedTokenIds.length === 0) {
      return cachedTokens;
    }

    const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
    rows.forEach((row) => {
      const tokenId = row.token_id;
      const cachedToken = new CachedToken(row);
      tokenCache.set(tokenId, cachedToken);
      cachedTokens.set(tokenId, cachedToken);
    });

    return cachedTokens;
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/tokens.js (L724-727)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length > 0) {
    const cachedTokens = await TokenService.getCachedTokens(new Set([tokenId]));
    const decimals = cachedTokens.get(tokenId)?.decimals ?? null;
```
