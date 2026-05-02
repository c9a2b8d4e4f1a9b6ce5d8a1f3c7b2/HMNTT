### Title
Unbounded LRU Token Cache Flooding via Unauthenticated REST API Enables Persistent DoS on Token Metadata Lookups

### Summary
The `tokenCache` in `rest/service/tokenService.js` is a `quick-lru` instance configured with only `maxSize` and no `maxAge`/TTL. Because the REST API exposes no rate-limiting middleware, an unauthenticated attacker can enumerate accounts with distinct token associations, filling the 100,000-entry LRU cache and continuously evicting legitimate entries. Every subsequent legitimate request for an evicted token ID incurs a synchronous DB round-trip, exhausting the 10-connection pool and degrading service for all users.

### Finding Description
**Code location:** `rest/service/tokenService.js`, lines 12–14 (cache construction) and lines 136–161 (`getCachedTokens`).

```js
// lines 12-14
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,   // default 100,000 — no maxAge
});
```

```js
// lines 136-161
async getCachedTokens(tokenIds) {
  const uncachedTokenIds = [];
  tokenIds.forEach((tokenId) => {
    const cachedToken = tokenCache.get(tokenId);
    if (cachedToken) { ... } else { uncachedTokenIds.push(tokenId); }
  });
  if (uncachedTokenIds.length === 0) return cachedTokens;
  const rows = await super.getRows(TokenService.tokenCacheQuery, [uncachedTokenIds]);
  rows.forEach((row) => { tokenCache.set(row.token_id, ...); });
  return cachedTokens;
}
```

**Root cause / failed assumption:** The cache has no TTL (`maxAge` is absent), so entries only leave via LRU eviction when `maxSize` is reached. The REST API stack (`rest/server.js`) applies no per-IP or global rate-limiting middleware — only `cors`, `compression`, `httpContext`, `requestLogger`, and an optional `authHandler` that does not throttle unauthenticated callers. The design assumes the cache will remain warm for frequently-used token IDs, but this assumption breaks under adversarial enumeration.

**Exploit flow:**
1. Attacker enumerates account IDs (publicly available on-chain) that collectively hold more than 100,000 distinct token associations.
2. For each account, attacker issues `GET /api/v1/accounts/{id}/tokens` (or any endpoint that calls `getTokenAccounts` → `getCachedTokens`).
3. Each response causes `getCachedTokens` to insert the account's token IDs into `tokenCache`. Once the cache reaches `maxSize`, every new insertion evicts the LRU entry.
4. Attacker cycles through accounts in a round-robin pattern, keeping the cache perpetually full of attacker-chosen token IDs and evicting legitimate ones.
5. Legitimate users querying their own accounts find their token IDs absent from cache, forcing a DB query on every request.

**Why existing checks fail:** There is no per-IP rate limit, no request-per-second throttle, and no connection-level guard on the REST API path. The DB pool cap of 10 connections (`maxConnections: 10`, `statementTimeout: 20000 ms`) means that even a modest flood of cache-miss requests can saturate the pool, causing queued requests to time out.

### Impact Explanation
Every cache miss triggers `SELECT decimals, freeze_status, kyc_status, token_id FROM token WHERE token_id = any($1)` against the database. With the 10-connection pool exhausted, legitimate token-balance queries queue or time out, returning HTTP 500/503 responses. Users relying on the mirror node to read token metadata (decimals, freeze/KYC status) before constructing transactions receive errors or stale fallback data, degrading the reliability of the public API. The impact is **service degradation and availability loss**, not direct on-chain fund movement; the "direct loss of funds" framing in the question is overstated — evicted entries are re-fetched from DB rather than served incorrectly, so data accuracy is preserved when the DB responds, but availability is not.

### Likelihood Explanation
The attack requires no credentials, no special network position, and no on-chain capability. Token and account IDs are public. A single attacker with a modest HTTP client can sustain the flood indefinitely. The Hedera mainnet has well over 100,000 distinct token IDs, making the precondition trivially satisfiable. The attack is repeatable and cheap.

### Recommendation
1. **Add TTL to the token cache:** Pass `maxAge` (e.g., 300,000 ms) to the `quickLru` constructor so entries expire and the cache self-heals.
2. **Add rate limiting to the REST API:** Introduce a per-IP token-bucket middleware (e.g., `express-rate-limit`) analogous to the `bucket4j` throttle already present in the web3 module.
3. **Bound per-request token ID fan-out:** Cap the number of token IDs passed to `getCachedTokens` in a single call to limit the blast radius of any single request.
4. **Consider a negative-entry cache:** Cache DB misses (non-existent token IDs) with a short TTL to prevent repeated DB hits for phantom IDs.

### Proof of Concept
```bash
# 1. Collect >100,000 distinct account IDs from the public mirror node
# 2. For each account, fire a request that triggers getCachedTokens:
for ACCOUNT_ID in $(seq 1 200000); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.${ACCOUNT_ID}/tokens" &
done
wait

# 3. Now query a legitimate account whose tokens were previously cached:
curl "https://<mirror-node>/api/v1/accounts/0.0.1234/tokens"
# Expected: response latency spikes; DB query fires on every request instead of cache hit.
# Under sustained flood: HTTP 500/503 as the 10-connection DB pool is exhausted.
```