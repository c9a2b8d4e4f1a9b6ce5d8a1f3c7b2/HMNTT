### Title
Uncached Database Lookup for EVM Address Resolution Enables Unauthenticated Non-Network DoS

### Summary
`getEncodedId()` in `rest/service/entityService.js` delegates EVM address resolution to `getEntityIdFromEvmAddress()`, which executes a raw database query on every invocation with no caching of results — including negative (not-found) results. The `parseCached` LRU cache in `rest/entityId.js` only caches the parsed `EntityId` object, not the database lookup outcome. An unprivileged attacker can sustain arbitrary database load by repeatedly submitting valid EVM address strings (with or without a realm prefix matching `evmAddressShardRealmRegex`) that do not exist in the database.

### Finding Description

**Exact code path:**

`getEncodedId()` at [1](#0-0)  calls `EntityId.parseString()` (line 121), then branches on `entityId.evmAddress === null` (line 122). For any opaque EVM address (one whose first 12 bytes are not all-zero, or whose num exceeds `maxNum`), `evmAddress` is non-null, so execution always falls to:

```js
await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

`getEntityIdFromEvmAddress` at [2](#0-1)  issues a raw SQL query every single invocation:

```sql
select id from entity where deleted <> true and evm_address = $1
```

There is no cache here — no result is stored, positive or negative.

**Why `parseCached` does not help:**

`parseCached` at [3](#0-2)  caches only the `EntityId` object (the parsing result). It calls `cache.set(key, entityId)` at line 331, where `entityId` carries `evmAddress = 'abcdef...'` and `num = null`. This cached object is returned on subsequent calls — but `getEncodedId` then unconditionally calls `getEntityIdFromEvmAddress` again because `entityId.evmAddress !== null`. The cache eliminates re-parsing overhead only; the database is still queried on every request.

**Realm-prefix trigger path:**

`evmAddressShardRealmRegex` at [4](#0-3)  is `/^(\d{1,4}\.)?(\d{1,5}\.)?[A-Fa-f0-9]{40}$/`. An input like `0.abcdef1234567890abcdef1234567890abcdef12` passes `isValidEntityId`, enters `parseFromString` at [5](#0-4) , and since `shard === systemShard` and `realm === systemRealm` (both 0), the shard/realm guard at line 246 does not throw. The address is classified as opaque (prefix ≠ `longFormEvmAddressPrefix`), `evmAddress` is set non-null, and the DB lookup is triggered. Notably, `0.abcdef...` and `abcdef...` produce different `parseCached` keys, so both bypass each other's parse cache while still hitting the DB.

### Impact Explanation

Every HTTP request carrying a unique valid EVM address (40 hex chars, optionally prefixed with `0.`) that is absent from the database causes one uncached `SELECT` against the `entity` table. With 16^40 possible addresses, an attacker has an effectively unlimited supply of unique inputs. Sustained high-rate requests translate directly to proportional database query load, potentially exhausting connection pools or query throughput, degrading or denying service to legitimate users. The affected endpoints include account, contract, token, and transaction lookups — all of which call `getEncodedId()`.

### Likelihood Explanation

No authentication or authorization is required. No rate limiting is present in `entityService.js` or visible in the service layer. The attack requires only the ability to send HTTP requests and knowledge of the public API format (documented). Generating unique valid EVM addresses is trivial (e.g., random 40-hex-char strings). The attack is fully repeatable and automatable with standard HTTP tooling.

### Recommendation

1. **Cache negative DB results**: In `getEntityIdFromEvmAddress`, store a sentinel value (e.g., `null` or a dedicated `NOT_FOUND` marker) in a bounded LRU cache keyed by the hex EVM address. Respect a short TTL (e.g., 30–60 s) to avoid stale negatives.
2. **Alternatively, unify caching**: Extend `parseCached` or introduce a second cache layer in `getEncodedId` that stores the final resolved entity ID (including null/not-found) keyed by the normalized EVM address string.
3. **Add rate limiting**: Apply per-IP or per-client rate limiting at the API gateway or middleware layer for endpoints that invoke `getEncodedId`.
4. **Input validation tightening**: Consider rejecting EVM addresses with non-system shard/realm prefixes early (before DB access) rather than only inside `parseFromString`.

### Proof of Concept

```bash
# Generate N unique random EVM addresses and flood the endpoint
for i in $(seq 1 10000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/accounts/0.${ADDR}" &
done
wait
```

Each request hits `getEncodedId` → `parseString` (parse cached after first hit per address) → `getEntityIdFromEvmAddress` → one `SELECT` against `entity.evm_address`. With 10,000 unique addresses, 10,000 DB queries are issued with no cache protection. Repeating with fresh addresses sustains the load indefinitely.

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

**File:** rest/entityId.js (L39-39)
```javascript
const evmAddressShardRealmRegex = /^(\d{1,4}\.)?(\d{1,5}\.)?[A-Fa-f0-9]{40}$/;
```

**File:** rest/entityId.js (L239-260)
```javascript
const parseFromString = (id, error) => {
  const parts = stripHexPrefix(id).split('.');
  const numOrEvmAddress = parts[parts.length - 1];
  const shard = parts.length === 3 ? BigInt(parts.shift()) : systemShard;
  const realm = parts.length === 2 ? BigInt(parts.shift()) : systemRealm;

  if (isValidEvmAddressLength(numOrEvmAddress.length)) {
    if (shard !== systemShard || realm !== systemRealm) {
      throw error(`Invalid shard or realm for EVM address ${id}`);
    }

    let [prefix, num] = parseFromEvmAddress(numOrEvmAddress);

    if (prefix !== longFormEvmAddressPrefix || num > maxNum) {
      return [shard, realm, null, numOrEvmAddress]; // Opaque EVM address
    } else {
      return [shard, realm, num, null]; // Account num alias
    }
  }

  return [shard, realm, BigInt(numOrEvmAddress), null];
};
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
