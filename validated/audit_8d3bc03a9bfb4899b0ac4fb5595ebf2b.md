All code references in the report were verified against the actual source. Here is the result:

---

Audit Report

## Title
Permanent Stale Freeze-Status Cache Poisoning via Unprivileged Token Endpoint Query

## Summary
`putTokenCache()` in `rest/service/tokenService.js` implements a strict set-if-absent policy with no TTL and no update path. Once a token's `freeze_status` is cached, it is never refreshed. If the token's freeze key is subsequently removed on-chain (changing the DB value to `0` / NOT_APPLICABLE), the mirror node API continues serving the stale FROZEN status from cache indefinitely, causing downstream applications to incorrectly treat the token as frozen.

## Finding Description

**`putTokenCache()` — unconditional early return on cache hit:**

`putTokenCache()` returns immediately if the token is already cached, with no mechanism to update the stored value. [1](#0-0) 

**No TTL on the `quick-lru` instance:**

The cache is initialised with only `maxSize`; no `maxAge` is set, so entries never expire by time. [2](#0-1) 

**`getCachedTokens()` — cache hits bypass the DB entirely:**

Only cache misses trigger a DB query; hits are returned directly from the stale in-memory map. [3](#0-2) 

**Stale `freezeStatus` used as fallback in `getTokenAccounts()`:**

The cached token-level `freeze_status` is applied to every `token_account` row whose own column is `NULL`. [4](#0-3) 

**Test suite explicitly validates the never-update semantic as intentional:**

The test puts a token, then puts it again with a different `decimals` value and asserts the original copy is still returned — confirming the set-if-absent behaviour is by design, not an accidental omission. [5](#0-4) 

**Root cause:** The cache design assumes token-level `freeze_status` is immutable once set. On Hedera, a token admin can remove the freeze key at any time, transitioning `freeze_status` from `1` (FROZEN) or `2` (UNFROZEN) to `0` (NOT_APPLICABLE) in the DB. The cache has no mechanism to observe or react to this on-chain state change.

## Impact Explanation

Any application (wallet, DEX, custodian) that calls the mirror node's account-token-relationship endpoint and inspects `freeze_status` to gate transfer decisions will see `FROZEN` for a token whose freeze key has been removed. This can:

- Block legitimate fund transfers for all token holders whose `token_account.freeze_status` is `NULL` (the fallback path).
- Persist indefinitely — until the process restarts or the LRU cache evicts the entry under memory pressure — with no operator-visible signal that the data is stale.
- Affect every consumer of the API simultaneously.

## Likelihood Explanation

- **No privilege required.** Any anonymous HTTP client can issue `GET /api/v1/tokens` or `GET /api/v1/tokens/:tokenId` to populate the cache, as `putTokenCache()` is called from both public endpoints in `rest/tokens.js`.
- **Trivially repeatable.** A single request before the freeze key is removed is sufficient; precise timing is not required because the cache is populated on every cold miss.
- **Self-sustaining.** Once cached, subsequent legitimate queries reinforce the stale entry (they hit the cache and never reach the DB), so the window of incorrect data is not bounded by request rate.
- **Realistic scenario.** Token admins routinely remove freeze keys as part of token lifecycle management.

## Recommendation

1. **Add a TTL** to the `quick-lru` instance (e.g., `maxAge: config.cache.token.maxAge`) so entries expire and are re-fetched from the DB after a bounded interval.
2. **Remove the early-return guard** in `putTokenCache()` (or replace it with an upsert) so that a fresher value from a token-info query can overwrite a stale cached entry.
3. **Invalidate or refresh the cache entry** whenever the mirror node ingests a `TokenUpdate` transaction that removes the freeze key.

## Proof of Concept

1. Token `0.0.500` exists in the DB with `freeze_status = 1` (FROZEN) and a valid freeze key.
2. Attacker (or any user) issues `GET /api/v1/tokens/0.0.500`. `getTokenInfoRequest()` calls `putTokenCache({token_id: 500, freeze_status: 1, ...})`. Cache now holds `freezeStatus = 1` for token 500. [1](#0-0) 
3. Token admin submits a `TokenUpdateTransaction` removing the freeze key. The mirror node ingests the transaction; the `token` table row for `0.0.500` is updated to `freeze_status = 0`.
4. Any subsequent call to `GET /api/v1/accounts/:accountId/tokens` for an account associated with token 500 whose `token_account.freeze_status` is `NULL` triggers `getTokenAccounts()` → `getCachedTokens()`. The cache hit returns `freezeStatus = 1`; the DB is never queried. [3](#0-2) 
5. The response contains `"freeze_status": "FROZEN"` despite the on-chain state being NOT_APPLICABLE. This persists for the lifetime of the process or until LRU eviction. [4](#0-3)

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L109-109)
```javascript
        row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
```

**File:** rest/service/tokenService.js (L121-129)
```javascript
  putTokenCache(token) {
    const tokenId = token.token_id;
    if (tokenCache.has(tokenId)) {
      return;
    }

    const cachedToken = new CachedToken(token);
    tokenCache.set(tokenId, cachedToken);
  }
```

**File:** rest/service/tokenService.js (L139-145)
```javascript
    tokenIds.forEach((tokenId) => {
      const cachedToken = tokenCache.get(tokenId);
      if (cachedToken) {
        cachedTokens.set(tokenId, cachedToken);
      } else {
        uncachedTokenIds.push(tokenId);
      }
```

**File:** rest/__tests__/service/tokenService.test.js (L205-207)
```javascript
    // put again, note some fields have different value, to validate the service returns the previous copy
    TokenService.putTokenCache({...token, decimals: 3});
    await expect(TokenService.getCachedTokens(new Set([200]))).resolves.toStrictEqual(expected);
```
