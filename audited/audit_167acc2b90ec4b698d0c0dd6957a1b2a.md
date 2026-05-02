### Title
Unauthenticated DB Query Storm via Non-Existent EVM Address Lookups with No Negative Caching

### Summary
`getEntityIdFromEvmAddress()` in `rest/service/entityService.js` executes a direct database query for every EVM address lookup with no caching of negative (not-found) results. The response-level Redis cache explicitly skips non-2xx responses, meaning 404 results from non-existent EVM addresses are never cached. An unprivileged attacker can generate an unbounded stream of syntactically valid but non-existent EVM addresses, each forcing a fresh DB query, with no rate limiting present in the REST middleware stack.

### Finding Description

**Exact code path:**

`getEntityIdFromEvmAddress()` at [1](#0-0)  executes `entityFromEvmAddressQuery` — `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` — directly against the database on every call. There is no in-process or distributed cache wrapping this DB call.

**Root cause — no negative result caching:**

The `entityId.js` LRU cache at [2](#0-1)  only caches the *parsed* `EntityId` object (the string-to-struct conversion). It does not cache the DB lookup result. The DB query in `getEntityIdFromEvmAddress()` is always executed regardless of whether the same address was seen before.

The Redis response cache in `responseCacheUpdateHandler` at [3](#0-2)  only stores responses when `httpStatusCodes.isSuccess(res.statusCode)` is true. A 404 `NotFoundError` thrown at [4](#0-3)  is never cached, so every repeated or unique non-existent EVM address request bypasses the cache entirely.

**No rate limiting:**

The REST middleware stack exported from [5](#0-4)  contains `authHandler`, `openApiValidator`, response cache handlers, and `responseHandler` — no rate limiter or throttle middleware is present.

**Exploit flow:**

`getEncodedId()` at [6](#0-5)  is the entry point. When the input passes `EntityId.isValidEntityId()` and the parsed `entityId.evmAddress` is non-null, it calls `getEntityIdFromEvmAddress()` unconditionally. A valid EVM address is any 40-character hex string (optionally prefixed with `0x` or `shard.realm.`), as defined by the regex at [7](#0-6) . There are 2¹⁶⁰ possible valid addresses, making address-space exhaustion impossible.

### Impact Explanation
Every request with a unique valid-format but non-existent EVM address issues one DB query that returns zero rows. With no negative caching and no rate limiting, a single attacker can sustain thousands of DB queries per second. The DB connection pool becomes saturated, increasing query latency for all mirror node users. Since the mirror node REST API is a shared read service, degradation affects all consumers including downstream applications relying on entity resolution.

### Likelihood Explanation
No authentication or API key is required. The attacker only needs to generate 40-character hex strings — trivially done with any scripting language. The attack is repeatable, scalable across multiple source IPs, and requires no knowledge of the system beyond the public API spec at [8](#0-7) . Any endpoint that resolves an account/contract/entity by EVM address is a valid attack vector.

### Recommendation
1. **Cache negative results**: Wrap `getEntityIdFromEvmAddress()` with a short-TTL (e.g., 5–30 s) in-process or Redis cache keyed on the EVM address bytes, including null/not-found results.
2. **Add rate limiting middleware** to the REST service (e.g., `express-rate-limit`) scoped per IP or API key, applied before entity resolution.
3. **Cache 404 responses** in the Redis response cache with a short TTL (modify the condition in `responseCacheUpdateHandler` to include 404 responses for EVM address endpoints).
4. Consider adding a DB-level query timeout or connection pool limit guard to bound the blast radius.

### Proof of Concept
```bash
# Generate and send 10,000 requests with unique valid but non-existent EVM addresses
for i in $(seq 1 10000); do
  ADDR=$(openssl rand -hex 20)  # 40 hex chars = valid EVM address format
  curl -s "https://<mirror-node>/api/v1/accounts/0x${ADDR}" &
done
wait
```
Each request passes format validation, reaches `getEntityIdFromEvmAddress()`, executes `SELECT id FROM entity WHERE deleted <> true AND evm_address = $1` against the DB, gets zero rows, returns 404 — which is never cached. The DB receives 10,000 queries with no cache hits. Scaling this across multiple clients or using async HTTP clients (e.g., `ab`, `wrk`, `hey`) amplifies the effect linearly.

### Citations

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

**File:** rest/service/entityService.js (L118-137)
```javascript
  async getEncodedId(entityIdString, requireResult = true, paramName = filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS) {
    try {
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
      } else if (AccountAlias.isValid(entityIdString)) {
        return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
      }
    } catch (ex) {
      if (ex instanceof InvalidArgumentError) {
        throw InvalidArgumentError.forParams(paramName);
      }
      // rethrow
      throw ex;
    }

    throw InvalidArgumentError.forParams(paramName);
  }
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

**File:** rest/entityId.js (L301-333)
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
};
```

**File:** rest/middleware/responseCacheHandler.js (L95-97)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
```

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```

**File:** rest/api/v1/openapi.yml (L2881-2898)
```yaml
      example: "0000000000000000000000000000000000001f41"
    EvmAddressWithShardRealm:
      type: string
      description: A network entity encoded as an EVM address in hex.
      format: binary
      minLength: 40
      maxLength: 60
      pattern: '^(\d{1,10}\.){0,2}[A-Fa-f0-9]{40}$'
      example: "0x0000000000000000000000000000000000001f41"
    EvmAddressNullable:
      type: string
      description: A network entity encoded as an EVM address in hex.
      format: binary
      minLength: 40
      maxLength: 42
      nullable: true
      pattern: "^(0x)?[A-Fa-f0-9]{40}$"
      example: "0x0000000000000000000000000000000000001f41"
```
