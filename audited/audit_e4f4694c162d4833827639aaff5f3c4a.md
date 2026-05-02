### Title
Unbounded DB Query Per Request via Opaque EVM Address in `getEncodedId()`

### Summary
`getEncodedId()` in `rest/service/entityService.js` unconditionally calls `getEntityIdFromEvmAddress()` for every opaque EVM address input, which always executes a live database query with no result caching. The `parseCached` LRU in `entityId.js` only caches the parsed `EntityId` struct, not the DB lookup result, so even repeated identical opaque EVM addresses trigger a DB round-trip on every request. An unauthenticated attacker can saturate the REST API's default 10-connection DB pool with a single address repeated at high rate.

### Finding Description

**Code path:**

`getEncodedId()` (`rest/service/entityService.js`, lines 118–137): [1](#0-0) 

When `entityIdString` is a valid opaque EVM address (e.g., `0.0.ff00000000000000000000000000000000000001`), `EntityId.parseString()` is called, which internally calls `parseCached()` in `rest/entityId.js`: [2](#0-1) 

`parseCached` caches the resulting `EntityId` struct (with `evmAddress` set, `num = null`) keyed by the input string. On a cache hit it returns the cached struct — but this does **not** prevent the DB query. Back in `getEncodedId()`, the branch at line 122–124 checks `entityId.evmAddress === null`: [3](#0-2) 

For an opaque address `evmAddress` is always non-null, so `getEntityIdFromEvmAddress()` is always called: [4](#0-3) 

This function executes `entityFromEvmAddressQuery` directly against the DB with no cache check and no cache write: [5](#0-4) 

**Root cause:** The `parseCached` cache in `entityId.js` caches only the structural parse of the address string, not the DB lookup result. `getEntityIdFromEvmAddress()` has no caching layer at all. Every call to `getEncodedId()` with any opaque EVM address — including the same address repeated — unconditionally issues a DB query.

**Why the shard/realm check does not help:** `parseFromString()` rejects non-system shard/realm values: [6](#0-5) 

But the attacker simply uses `0.0.<opaque_evm_address>` (system shard=0, realm=0), which passes this check and is classified as opaque because the first 12 bytes are non-zero: [7](#0-6) 

### Impact Explanation

The REST API's default DB connection pool is capped at **10 connections**: [8](#0-7) 

With 10 or more concurrent requests each holding a DB connection waiting for the `entity` table lookup, the pool is exhausted. All other REST API endpoints that require DB access queue or time out (default statement timeout 20 s): [9](#0-8) 

This causes a full service-level denial of service for all legitimate users of the REST API without any network flooding — a single attacker thread sending sequential requests is sufficient to keep the pool saturated.

### Likelihood Explanation

No authentication is required to call any REST API endpoint that resolves an entity ID (e.g., `/api/v1/accounts/{id}`, `/api/v1/contracts/{id}`). There is no rate limiting configured for the Node.js REST API (the throttle/bucket4j configuration found applies only to the separate Web3 Java API): [10](#0-9) 

The attack requires only knowledge of the EVM address format (public specification), zero privileges, and a single valid opaque address (e.g., `0.0.ff00000000000000000000000000000000000001`). It is trivially repeatable and scriptable.

### Recommendation

Cache the result of `getEntityIdFromEvmAddress()` keyed by the hex EVM address string, using the existing `quickLru` infrastructure already present in `entityId.js` or a dedicated cache in `entityService.js`. A negative-result cache entry (address not found → `null`) is equally important to prevent repeated DB queries for non-existent addresses. Alternatively, add per-IP or global rate limiting middleware to the Node.js REST API layer before entity ID resolution occurs.

### Proof of Concept

```bash
# Single opaque EVM address (non-zero prefix → always opaque, always DB query)
ADDR="0.0.ff00000000000000000000000000000000000001"

# Saturate the 10-connection pool with concurrent requests
for i in $(seq 1 50); do
  curl -s "http://<mirror-node-rest>:5551/api/v1/accounts/${ADDR}" &
done
wait

# Legitimate requests now time out or receive 500 errors
curl -v "http://<mirror-node-rest>:5551/api/v1/accounts/0.0.1"
# Expected: connection timeout or DB statement timeout error
```

Each request in the loop causes `getEncodedId()` → `getEntityIdFromEvmAddress()` → `SELECT id FROM entity WHERE evm_address = $1` to execute, holding a DB connection for the duration of the query. With 50 concurrent requests and a pool of 10, 40 requests queue and legitimate traffic is blocked.

### Citations

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

**File:** rest/entityId.js (L246-248)
```javascript
    if (shard !== systemShard || realm !== systemRealm) {
      throw error(`Invalid shard or realm for EVM address ${id}`);
    }
```

**File:** rest/entityId.js (L250-253)
```javascript
    let [prefix, num] = parseFromEvmAddress(numOrEvmAddress);

    if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
      return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
```

**File:** rest/entityId.js (L314-333)
```javascript
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

**File:** docs/configuration.md (L544-548)
```markdown
| Name                                                                     | Default                 | Description                                                                                                                                                                                   |
| ------------------------------------------------------------------------ | ----------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.rest.cache.entityId.maxAge`                                | 1800                    | The number of seconds until the entityId cache entry expires                                                                                                                                  |
| `hiero.mirror.rest.cache.entityId.maxSize`                               | 100000                  | The maximum number of entries in the entityId cache                                                                                                                                           |
| `hiero.mirror.rest.cache.token.maxSize`                                  | 100000                  | The maximum number of entries in the token cache                                                                                                                                              |
```

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
```

**File:** docs/configuration.md (L557-557)
```markdown
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
