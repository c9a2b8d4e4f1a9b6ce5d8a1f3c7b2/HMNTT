### Title
Permanent Stale Freeze-Status Cache Poisoning via Unprivileged Token Endpoint Query

### Summary
`putTokenCache()` in `rest/service/tokenService.js` implements a strict "set-if-absent" policy with no TTL, no cache invalidation, and no update path. Any unprivileged user who queries a token endpoint while a token has `freeze_status = 1` (FROZEN) causes that value to be permanently cached. After the token's freeze key is removed on-chain (changing the DB value to `0` / NOT_APPLICABLE), the mirror node API continues serving the stale FROZEN status from cache for the lifetime of the process or until LRU eviction, causing downstream applications to incorrectly treat the token as frozen.

### Finding Description

**Exact code location — `putTokenCache()`, lines 121–129:**

```js
putTokenCache(token) {
  const tokenId = token.token_id;
  if (tokenCache.has(tokenId)) {
    return;           // ← unconditional early return; cache is NEVER updated
  }
  const cachedToken = new CachedToken(token);
  tokenCache.set(tokenId, cachedToken);
}
``` [1](#0-0) 

The cache is a `quick-lru` instance initialised with only `maxSize` — **no `maxAge`/TTL is set**, so entries never expire by time:

```js
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
``` [2](#0-1) 

`getCachedTokens()` has the same "no-refresh" behaviour: if a token is already in the cache it is returned immediately without a DB round-trip:

```js
const cachedToken = tokenCache.get(tokenId);
if (cachedToken) {
  cachedTokens.set(tokenId, cachedToken);   // ← served from stale cache
} else {
  uncachedTokenIds.push(tokenId);           // ← only misses go to DB
}
``` [3](#0-2) 

`putTokenCache()` is called from two public, unauthenticated endpoints:

- `GET /api/v1/tokens` → `getTokensRequest()` line 399
- `GET /api/v1/tokens/:tokenId` → `getTokenInfoRequest()` line 562 [4](#0-3) [5](#0-4) 

The stale cached `freezeStatus` is then consumed by `getTokenAccounts()` as a fallback for any `token_account` row whose own `freeze_status` column is `NULL`:

```js
row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
``` [6](#0-5) 

The test suite explicitly documents and validates this "never-update" semantic as intentional, confirming there is no accidental omission of an update path: [7](#0-6) 

**Root cause:** The cache design assumes token-level `freeze_status` is immutable once set, but on Hedera a token admin can remove the freeze key at any time, transitioning `freeze_status` from `1`/`2` to `0` (NOT_APPLICABLE) in the DB. The cache has no mechanism to observe or react to this on-chain state change.

### Impact Explanation

Any application (wallet, DEX, custodian) that calls the mirror node's account-token-relationship endpoint and inspects `freeze_status` to gate transfer decisions will see `FROZEN` for a token whose freeze key has been removed. This can:

- Block legitimate fund transfers for all token holders whose `token_account.freeze_status` is `NULL` (the fallback path).
- Persist indefinitely — until the process restarts or the LRU cache evicts the entry under memory pressure — with no operator-visible signal that the data is stale.
- Affect every consumer of the API simultaneously, not just the attacker's session.

Severity: **High** — data integrity failure in a security-sensitive field with no automatic recovery.

### Likelihood Explanation

- **No privilege required.** Any anonymous HTTP client can issue `GET /api/v1/tokens` or `GET /api/v1/tokens/:tokenId` to populate the cache.
- **Trivially repeatable.** A single request before the freeze key is removed is sufficient; the attacker does not need to time the request precisely because the cache is populated on every cold miss.
- **Self-sustaining.** Once cached, subsequent legitimate queries reinforce the stale entry (they hit the cache and never reach the DB), so the window of incorrect data is not bounded by request rate.
- **Realistic scenario.** Token admins routinely remove freeze keys as part of token lifecycle management (e.g., migrating to a new key, or permanently removing freeze capability).

### Recommendation

1. **Add a TTL** to the `quick-lru` instance via its `maxAge` option, sized to an acceptable staleness window (e.g., 60 seconds):
   ```js
   const tokenCache = new quickLru({
     maxSize: config.cache.token.maxSize,
     maxAge: config.cache.token.maxAge,   // add this
   });
   ```
2. **Remove the early-return guard in `putTokenCache()`** so that a fresher DB-sourced value always wins, or rename the function to make its "set-if-absent" contract explicit and audit all callers.
3. **Invalidate or refresh the cache entry** whenever `getTokenInfoRequest()` fetches a token directly from the DB (it already has the fresh row at line 560; it should unconditionally overwrite the cache, not skip if present).
4. **Do not use the token-level cache as a fallback for `freeze_status`** in `getTokenAccounts()`. Account-level freeze status should come exclusively from `token_account.freeze_status`; if that column is `NULL`, the correct answer is NOT_APPLICABLE (0), not the potentially stale token-level value.

### Proof of Concept

**Preconditions:**
- Token `0.0.500` exists with `freeze_key` set and `freeze_status = 1` (FROZEN) in the DB.
- Mirror node process is running with a cold cache (or token 500 not yet cached).

**Steps:**

1. **Attacker (unprivileged) sends:**
   ```
   GET /api/v1/tokens/0.0.500
   ```
   → `getTokenInfoRequest()` queries DB, gets `freeze_status = 1`, calls `putTokenCache({token_id: 500, freeze_status: 1, ...})`. Cache now holds `freezeStatus = 1` for token 500.

2. **Token admin removes the freeze key on-chain** (e.g., via `TokenUpdateTransaction` with an empty freeze key). The DB `token.freeze_status` for token 500 is updated to `0` (NOT_APPLICABLE).

3. **Any user queries account token relationships:**
   ```
   GET /api/v1/accounts/0.0.1234/tokens
   ```
   → `getTokenAccounts()` fetches `token_account` rows. For accounts where `token_account.freeze_status IS NULL`, line 109 executes:
   ```js
   row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
   // null ?? 1  →  1  (FROZEN — incorrect)
   ```
   The response reports `freeze_status: 1` (FROZEN) even though the freeze key no longer exists.

4. **Result:** The API permanently reports FROZEN for token 500 until process restart or LRU eviction. No operator action short of restarting the mirror-node REST service clears the incorrect cached value.

### Citations

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```

**File:** rest/service/tokenService.js (L109-110)
```javascript
        row.freeze_status = row.freeze_status ?? cachedToken.freezeStatus;
        row.kyc_status = row.kyc_status ?? cachedToken.kycStatus;
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

**File:** rest/tokens.js (L398-401)
```javascript
  const tokens = rows.map((r) => {
    TokenService.putTokenCache(r);
    return formatTokenRow(r);
  });
```

**File:** rest/tokens.js (L560-563)
```javascript
  const token = rows[0];
  if (filters.length === 0) {
    TokenService.putTokenCache(token);
  }
```

**File:** rest/__tests__/service/tokenService.test.js (L205-208)
```javascript
    // put again, note some fields have different value, to validate the service returns the previous copy
    TokenService.putTokenCache({...token, decimals: 3});
    await expect(TokenService.getCachedTokens(new Set([200]))).resolves.toStrictEqual(expected);
  });
```
