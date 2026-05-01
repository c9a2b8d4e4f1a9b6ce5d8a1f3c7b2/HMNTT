### Title
Unauthenticated EVM Address DB Lookup DoS via Unbounded Per-Request Entity Queries in `AccountController.getNftsByAccountId`

### Summary
The REST API endpoint `GET /api/v1/accounts/:idOrAliasOrEvmAddress/nfts` accepts any valid EVM address as a path parameter and unconditionally issues a live database query per request via `EntityService.getEntityIdFromEvmAddress()`. No rate limiting exists in the REST Node.js service, and the response cache only protects against repeated identical URLs. An attacker supplying a high volume of requests with distinct valid EVM addresses bypasses all caching and exhausts the database connection pool, denying service to legitimate consumers including gossip transaction record endpoints.

### Finding Description

**Exact code path:**

`rest/routes/accountRoute.js:15` registers the route with no authentication or rate-limiting middleware: [1](#0-0) 

`rest/controllers/accountController.js:90-91` calls `EntityService.getEncodedId()` unconditionally on every request: [2](#0-1) 

`rest/service/entityService.js:118-124` — when the input is a valid EVM address (non-parsable, i.e. `evmAddress !== null`), it always calls `getEntityIdFromEvmAddress()`: [3](#0-2) 

`rest/service/entityService.js:90-91` — `getEntityIdFromEvmAddress()` executes a live DB query on every invocation with no caching: [4](#0-3) 

The SQL query issued is: [5](#0-4) 

**Root cause and failed assumptions:**

1. **No rate limiting in the REST service.** The `ThrottleConfiguration`/`ThrottleManagerImpl` exist only in the `web3` Java service. A grep across `rest/**/*.js` for `rateLimit`, `throttle`, `express-rate`, or `limiter` returns no hits in production code. `server.js` applies no rate-limiting middleware to the accounts routes: [6](#0-5) 

2. **Response cache does not protect against distinct EVM addresses.** `responseCacheHandler.js` keys the cache on an MD5 of `req.originalUrl`: [7](#0-6) 
   Each unique EVM address produces a unique URL → unique cache key → cache miss → DB query.

3. **EntityId parsing cache does not cache DB results.** The `quickLru` cache in `entityId.js` caches only the parsed `EntityId` struct (shard/realm/num/evmAddress), not the result of the database lookup: [8](#0-7) 

4. **EVM address validation is permissive.** Any 40-hex-char string (with or without `0x`) passes `isValidEvmAddress()` and, if it is not a long-form num-alias, is treated as an opaque EVM address requiring a DB lookup: [9](#0-8) 

### Impact Explanation
Each HTTP request with a distinct valid EVM address maps 1:1 to a database query against the `entity` table. A sustained flood of such requests exhausts the PostgreSQL connection pool shared by all REST endpoints, including those serving gossip transaction records. Legitimate reads stall or time out, constituting a full denial of service for the mirror node REST API. Severity: **High** — no authentication required, no per-IP or global request budget enforced.

### Likelihood Explanation
The attack requires only an HTTP client and knowledge of the public API schema (documented in `openapi.yml`). Generating thousands of syntactically valid random 40-hex-char EVM addresses is trivial. The attacker needs no account, no token, and no privileged access. The attack is repeatable and automatable from a single host or a small botnet.

### Recommendation
1. **Add rate limiting to the REST Node.js service** — apply `express-rate-limit` (or equivalent) globally or specifically to the `/:idOrAliasOrEvmAddress/*` account sub-routes before the route handlers.
2. **Cache negative EVM address lookups** — introduce an in-process or Redis-backed cache in `EntityService.getEntityIdFromEvmAddress()` keyed on the EVM address bytes, with a short TTL (e.g., 5–30 s), so repeated or near-repeated lookups for non-existent addresses do not hit the DB.
3. **Validate EVM address format more strictly at the route level** — reject addresses that are syntactically valid but structurally implausible (e.g., all-zero, known-invalid ranges) before issuing any DB query.

### Proof of Concept
```bash
# Generate and fire 5000 requests with distinct random EVM addresses
for i in $(seq 1 5000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/accounts/0x${ADDR}/nfts" &
done
wait
```
Each request passes `isValidEvmAddress()`, is classified as an opaque EVM address (`evmAddress !== null`), skips the response cache (unique URL), and issues a fresh `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` query. With 5 000 concurrent requests the DB connection pool is saturated and all other REST endpoints — including gossip transaction record endpoints — begin returning errors or timing out.

### Citations

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** rest/controllers/accountController.js (L90-91)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
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

**File:** rest/server.js (L100-103)
```javascript
// accounts routes
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/entityId.js (L116-131)
```javascript
const isValidEvmAddress = (address, evmAddressType = constants.EvmAddressType.ANY) => {
  if (typeof address !== 'string') {
    return false;
  }

  if (evmAddressType === constants.EvmAddressType.ANY) {
    return evmAddressRegex.test(address) || evmAddressShardRealmRegex.test(address);
  }
  if (evmAddressType === constants.EvmAddressType.NO_SHARD_REALM) {
    return evmAddressRegex.test(address);
  }
  if (evmAddressType === constants.EvmAddressType.NUM_ALIAS) {
    return (evmAddressRegex.test(address) || evmAddressShardRealmRegex.test(address)) && !isEvmAddressAlias(address);
  }
  return evmAddressShardRealmRegex.test(address);
};
```

**File:** rest/entityId.js (L301-332)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});

/**
 * Parses entity ID string, can be shard.realm.num, realm.num, the encoded entity ID or an evm address.
 * @param {string} id
 * @param {boolean} allowEvmAddress
 * @param {number} evmAddressType
 * @param {Function} error
 * @return {EntityId}
 */
const parseCached = (id, allowEvmAddress, evmAddressType, error) => {
  const key = `${id}_${allowEvmAddress}_${evmAddressType}`;
  const value = cache.get(key);
  if (value) {
    return value;
  }

  if (!isValidEntityId(id, allowEvmAddress, evmAddressType)) {
    throw error();
  }
  const [shard, realm, num, evmAddress] =
    id.includes('.') || isValidEvmAddressLength(id.length) ? parseFromString(id, error) : parseFromEncodedId(id, error);
  if (evmAddress === null && (num > maxNum || realm > maxRealm || shard > maxShard)) {
    throw error();
  }

  const entityId = of(shard, realm, num, evmAddress);
  cache.set(key, entityId);
  return entityId;
```
