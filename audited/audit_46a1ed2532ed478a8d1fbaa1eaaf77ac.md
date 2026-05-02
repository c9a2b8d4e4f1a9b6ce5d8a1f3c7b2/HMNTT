### Title
Unauthenticated Per-Route DB Lookup Amplification via Random EVM Addresses on Account Sub-Routes

### Summary
All five account sub-routes (`/nfts`, `/rewards`, `/allowances/crypto`, `/allowances/tokens`, `/tokens`) independently call `EntityService.getEncodedId()`, which unconditionally executes a raw database query against the `entity` table for every EVM-address-format path parameter. There is no caching of negative (miss) results and no rate limiting in the REST layer, allowing any unauthenticated attacker to multiply DB load by a factor of five per unique address by hitting all five routes simultaneously.

### Finding Description

**Code path:**

`rest/routes/accountRoute.js` registers five routes, all accepting a free-form `:idOrAliasOrEvmAddress` path parameter: [1](#0-0) 

Each controller handler immediately calls `EntityService.getEncodedId()` with the raw path parameter: [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

Inside `getEncodedId()`, when the input matches the EVM address regex (`0x<40 hex chars>`), it unconditionally calls `getEntityIdFromEvmAddress()`: [7](#0-6) 

`getEntityIdFromEvmAddress()` executes a raw parameterized SQL query against the `entity` table on every invocation — no in-process cache, no negative-result cache: [8](#0-7) 

The query itself: [9](#0-8) 

**Root cause:** The REST Node.js `EntityService` (distinct from the Java importer's `EntityIdServiceImpl` which does have a cache) has no caching layer for EVM address lookups. The `entityFromEvmAddressQuery` is executed on every call. No rate-limiting middleware exists in the REST server — a grep for `rateLimit`, `throttle`, or `rateLimiter` across all `rest/**/*.js` returns zero results. The optional response cache (`responseCacheCheckHandler`) only caches full HTTP responses for successful hits, not negative DB lookups for unknown addresses. [10](#0-9) 

### Impact Explanation
An attacker sending concurrent requests to all five sub-routes with distinct random 20-byte EVM addresses causes five independent `SELECT` queries against the `entity` table per unique address per request cycle. Because the addresses are random and will never match, the response cache is never populated. The DB connection pool is consumed and the `entity` table index is repeatedly scanned. At scale this degrades query latency for all legitimate users sharing the same database. The impact is griefing/availability degradation with no economic damage to network participants, consistent with the Medium scope classification.

### Likelihood Explanation
No authentication, no API key, no rate limit, and no CAPTCHA is required. Any attacker with a script generating random hex strings and an HTTP client can trigger this. The attack is trivially repeatable, parallelizable across multiple source IPs, and requires zero on-chain resources or privileged access. The five-route multiplication factor means a single attacker thread produces five DB queries per request cycle.

### Recommendation
1. **Add a negative-result cache** in `EntityService.getEntityIdFromEvmAddress()` (e.g., a short-TTL in-process LRU cache keyed on the hex EVM address) so repeated misses for the same address do not hit the DB.
2. **Implement IP-based rate limiting** at the Express middleware layer (e.g., `express-rate-limit`) applied globally or specifically to the `/accounts/:id/*` route family.
3. **Consider a shared resolution step**: resolve the EVM address to an entity ID once at the router/middleware level and attach it to `req.locals`, rather than re-resolving independently in each controller handler.

### Proof of Concept
```bash
# Generate a random EVM address
ADDR=$(openssl rand -hex 20)

# Hit all five sub-routes concurrently with the same random address
# Each triggers one independent DB query; repeat with new addresses to sustain load
for i in $(seq 1 1000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/nfts" &
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/rewards" &
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/allowances/crypto" &
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/allowances/tokens" &
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/tokens" &
done
wait
```
Each iteration produces 5 DB queries against the `entity` table with no cache hits, no authentication check, and no rate-limit rejection.

### Citations

**File:** rest/routes/accountRoute.js (L15-19)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
router.getExt(getPath('rewards'), AccountController.listStakingRewardsByAccountId);
router.getExt(getPath('allowances/crypto'), CryptoAllowanceController.getAccountCryptoAllowances);
router.getExt(getPath('allowances/tokens'), TokenAllowanceController.getAccountTokenAllowances);
router.getExt(getPath('tokens'), TokenController.getTokenRelationships);
```

**File:** rest/controllers/accountController.js (L91-91)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/accountController.js (L171-171)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/cryptoAllowanceController.js (L77-77)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/tokenAllowanceController.js (L69-69)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/controllers/tokenController.js (L67-67)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-104)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
    if (rows.length === 0) {
      if (requireResult) {
        throw new NotFoundError();
      }

      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching evm address ${entityId}`);
      throw new Error(EntityService.multipleEvmAddressMatch);
    }

    return rows[0].id;
  }
```

**File:** rest/service/entityService.js (L118-124)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/server.js (L94-98)
```javascript
// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```
