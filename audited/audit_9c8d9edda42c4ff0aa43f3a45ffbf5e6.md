### Title
Unauthenticated LRU Cache Eviction Griefing via Shared `tokenCache` Singleton

### Summary
`tokenCache` in `rest/service/tokenService.js` is a process-wide `quickLru` singleton with no per-user isolation, no rate limiting, and no write throttle. Any unauthenticated caller can systematically query the `/accounts/:id/tokens` endpoint across many accounts to insert up to `config.cache.token.maxSize` (default 100,000) unique token IDs, triggering LRU eviction of entries used by other users and forcing those users' subsequent requests to incur additional DB round-trips. No authentication or privilege is required.

### Finding Description
**Code location:**
- Singleton declaration: `rest/service/tokenService.js` lines 12–14
- Cache population: `getCachedTokens()` lines 136–161
- Caller: `getTokenAccounts()` lines 96–115
- HTTP entry point: `GET /accounts/:id/tokens` → `TokenController.getTokenRelationships` → `TokenService.getTokenAccounts`

**Root cause:**
`tokenCache` is declared at module scope as a single shared `quickLru` instance:

```js
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,  // default 100,000
});
```

`getCachedTokens()` unconditionally writes every DB-fetched token into this shared cache:

```js
rows.forEach((row) => {
  const tokenId = row.token_id;
  const cachedToken = new CachedToken(row);
  tokenCache.set(tokenId, cachedToken);   // no guard, no quota
  cachedTokens.set(tokenId, cachedToken);
});
```

When the cache is full, `quick-lru` silently evicts the least-recently-used entry. There is no per-IP write quota, no rate limiter on the REST layer (confirmed: zero matches for `rateLimit|throttle` in `rest/**/*.js`), and no authentication requirement on the endpoint.

**Exploit flow:**
1. Attacker enumerates token IDs from the public `/api/v1/tokens` endpoint.
2. Attacker identifies accounts associated with many distinct tokens (also public data).
3. Attacker issues repeated `GET /accounts/:id/tokens?limit=100` requests across many accounts, each response causing up to 100 new token IDs to be written into `tokenCache`.
4. After ~1,000 requests (100,000 / 100 per page), the cache is saturated with attacker-chosen token IDs.
5. Any subsequent legitimate request for a token that was evicted misses the cache, falls through to `tokenCacheQuery` (`SELECT … FROM token WHERE token_id = any ($1)`), and consumes a DB connection from the pool (default max 10).
6. Attacker repeats continuously to keep the cache in a thrashed state.

**Why existing checks fail:**
- `putTokenCache()` has a `has()` guard, but `getCachedTokens()` (lines 153–158) bypasses it and writes directly via `tokenCache.set()`.
- No rate limiting exists anywhere in the REST layer for this endpoint.
- No TTL is configured on `tokenCache`; entries only leave via LRU eviction, so the attacker's entries persist until displaced.

### Impact Explanation
The direct impact is elevated DB query volume: every evicted token that a legitimate user requests causes an extra `SELECT` against the `token` table and consumes one of the 10 pooled DB connections. Under a sustained attack, this degrades response latency for all users querying token relationships and can approach DB connection pool exhaustion, causing request queuing or timeouts. Data correctness is not affected; the impact is availability/performance degradation (griefing).

### Likelihood Explanation
The attack requires no credentials, no on-chain assets, and no special knowledge beyond the public REST API. The Hedera mainnet has well over 100,000 tokens, so the attacker has ample unique IDs to work with. ~1,000 HTTP requests saturate the cache; a single machine with modest bandwidth can sustain this indefinitely. The attack is fully repeatable and scriptable.

### Recommendation
1. **Add a TTL to `tokenCache`**: Switch to a cache implementation that supports time-based expiry (e.g., `lru-cache` with `ttl`) so attacker-inserted entries age out.
2. **Rate-limit cache writes**: Track the number of distinct token IDs inserted per request and cap it (e.g., reject or skip cache writes beyond a per-request threshold).
3. **Apply API-level rate limiting**: Add per-IP rate limiting middleware (e.g., `express-rate-limit`) to the `/accounts/:id/tokens` route to bound the rate at which any single client can drive cache insertions.
4. **Consider a per-shard or segmented cache**: Partition `tokenCache` so that a flood of writes to one segment cannot evict entries in another.

### Proof of Concept
```bash
# Step 1: collect 1000+ distinct account IDs that hold different tokens
curl "https://<mirror-node>/api/v1/tokens?limit=100&order=asc" | jq '.tokens[].token_id'

# Step 2: for each token, get an associated account
for TOKEN_ID in $(seq 1 1000); do
  curl -s "https://<mirror-node>/api/v1/tokens/0.0.${TOKEN_ID}/balances?limit=1" \
    | jq -r '.balances[0].account'
done > accounts.txt

# Step 3: flood the cache with unique token IDs via account token relationship queries
while true; do
  while IFS= read -r ACCOUNT; do
    curl -s "https://<mirror-node>/api/v1/accounts/${ACCOUNT}/tokens?limit=100" > /dev/null &
  done < accounts.txt
  wait
done
# Result: tokenCache continuously thrashed; legitimate users' token lookups
# miss cache and hit DB, increasing DB connection pool pressure.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L96-115)
```javascript
  async getTokenAccounts(query) {
    const {sqlQuery, params} = this.getTokenRelationshipsQuery(query);
    const rows = await super.getRows(sqlQuery, params);
    if (rows.length === 0) {
      return [];
    }

    const tokenIds = rows.reduce((result, row) => result.add(row.token_id), new Set());
    const cachedTokens = await this.getCachedTokens(tokenIds);
    return rows.map((row) => {
      const cachedToken = cachedTokens.get(row.token_id);
      if (cachedToken) {
        row.decimals = cachedToken.decimals;
        row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
        row.kyc_status = row.kyc_status ?? cachedToken.kycStatus;
      }

      return new TokenAccount(row);
    });
  }
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

**File:** rest/controllers/tokenController.js (L66-75)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters);
    const query = this.extractTokensRelationshipQuery(filters, accountId);
    const tokenRelationships = await TokenService.getTokenAccounts(query);
    const tokens = tokenRelationships.map((token) => new TokenRelationshipViewModel(token));
```

**File:** rest/routes/accountRoute.js (L19-19)
```javascript
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);
```
