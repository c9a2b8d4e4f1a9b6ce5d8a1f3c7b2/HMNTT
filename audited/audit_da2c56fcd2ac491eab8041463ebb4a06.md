### Title
Unbounded Database Round-Trips via Non-Existent Account Alias Lookups in `getEncodedId()`

### Summary
The REST API's `EntityService.getEncodedId()` resolves account alias strings by executing a live database query on every request with no caching of results — including negative (not-found) results. An unprivileged attacker can flood the service with syntactically valid but non-existent alias strings, forcing a database round-trip per request, exhausting the connection pool (default max 10), and degrading service for all users.

### Finding Description

**Exact code path:**

`getEncodedId()` at [1](#0-0)  checks `AccountAlias.isValid(entityIdString)` and, if true, calls `getAccountIdFromAlias()` → `getAccountFromAlias()`, which unconditionally executes:

```sql
SELECT id FROM entity WHERE coalesce(deleted, false) <> true AND alias = $1
``` [2](#0-1) 

`getAccountFromAlias()` calls `super.getRows(...)` directly against the database pool with no caching layer: [3](#0-2) 

`BaseService.getRows()` issues a raw DB query every time: [4](#0-3) 

**Root cause — failed assumption:** The code assumes alias lookups are infrequent or that infrastructure-level rate limiting is always present. Neither is guaranteed. There is no in-process cache for alias→entity resolution. The `quickLru` cache in `entityId.js` only caches parsed `EntityId` objects (shard.realm.num format), not alias DB lookups: [5](#0-4) 

`AccountAlias.isValid()` accepts any string matching `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/`: [6](#0-5) 

This means an attacker can generate an unbounded set of syntactically valid alias strings (e.g., `AAAAAAAAAAAAAAAA`, `AAAAAAAAAAAAAAAB`, …) that all pass validation but resolve to nothing in the DB.

**Why existing checks fail:**
- The REST API middleware has no rate limiting — `requestHandler.js` only handles query parsing and logging: [7](#0-6) 
- The response cache (`responseCacheHandler`) only caches successful (2xx) responses, not 404s from missing aliases.
- The DB connection pool is capped at 10 connections by default: [8](#0-7) 
- The `tokenService.js` has a `quickLru` cache for tokens, but `EntityService` has no equivalent for alias lookups: [9](#0-8) 

### Impact Explanation
Each request with a valid-but-nonexistent alias consumes one DB connection for the duration of the query. With a pool of 10 connections and sustained alias flooding, legitimate requests queue or time out (20 s statement timeout). The `entity` table alias column lookup, while indexed, still incurs I/O and CPU on the DB server per request. This constitutes a non-network-based DoS: the attacker does not need to saturate bandwidth — only sustain a moderate request rate (tens of RPS) to hold the connection pool.

### Likelihood Explanation
No authentication or API key is required. The alias format is trivially enumerable — any uppercase base32 string passes `isValid()`. The attack is repeatable indefinitely from a single client or distributed across IPs. Infrastructure-level rate limiting (Traefik) is optional and not enforced by the application itself.

### Recommendation
1. **Add a negative-result cache in `EntityService`**: Use a bounded `quickLru` (similar to `tokenService.js`) keyed on the decoded alias bytes, caching both positive and negative (null) results with a short TTL (e.g., 30–60 s).
2. **Enforce application-level rate limiting** in the REST API middleware (e.g., `express-rate-limit`) per IP, independent of infrastructure.
3. **Add a minimum alias length check** in `AccountAlias.isValid()` to reject trivially short strings that are unlikely to be real Hedera public-key aliases (real aliases are 35+ bytes decoded).

### Proof of Concept

```bash
# Generate and send 1000 requests with unique valid base32 alias strings
for i in $(seq 1 1000); do
  ALIAS=$(python3 -c "import base64, os; print(base64.b32encode(os.urandom(32)).decode().rstrip('='))")
  curl -s "https://<mirror-node-host>/api/v1/accounts/$ALIAS" &
done
wait
```

Each request passes `AccountAlias.isValid()`, enters `getAccountFromAlias()`, executes `entityFromAliasQuery` against the DB, returns null (no entity found), and the result is discarded with no caching. With 10 concurrent connections in the pool, legitimate API traffic stalls. Repeating at 50+ RPS sustains the degradation.

### Citations

**File:** rest/service/entityService.js (L17-20)
```javascript
  static entityFromAliasQuery = `select ${Entity.ID}
                                 from ${Entity.tableName}
                                 where coalesce(${Entity.DELETED}, false) <> true
                                   and ${Entity.ALIAS} = $1`;
```

**File:** rest/service/entityService.js (L42-53)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);

    if (isEmpty(rows)) {
      return null;
    } else if (rows.length > 1) {
      logger.error(`Incorrect db state: ${rows.length} alive entities matching alias ${accountAlias}`);
      throw new Error(EntityService.multipleAliasMatch);
    }

    return new Entity(rows[0]);
  }
```

**File:** rest/service/entityService.js (L118-127)
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
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
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

**File:** rest/accountAlias.js (L10-44)
```javascript
const accountAliasRegex = /^(\d{1,5}\.){0,2}[A-Z2-7]+$/;
const noShardRealmAccountAliasRegex = /^[A-Z2-7]+$/;
const {common} = getMirrorConfig();

class AccountAlias {
  /**
   * Creates an AccountAlias object.
   * @param {string|null} shard
   * @param {string|null} realm
   * @param {string} base32Alias
   */
  constructor(shard, realm, base32Alias) {
    this.shard = AccountAlias.validate(shard, common.shard, 'shard');
    this.realm = AccountAlias.validate(realm, common.realm, 'realm');
    this.alias = base32.decode(base32Alias);
    this.base32Alias = base32Alias;
  }

  static validate(num, configured, name) {
    if (!isNil(num) && BigInt(num) !== configured) {
      throw new InvalidArgumentError(`Unsupported ${name} ${num}`);
    }
    return configured;
  }

  /**
   * Checks if the accountAlias string is valid
   * @param {string} accountAlias
   * @param {boolean} noShardRealm If shard realm is allowed as a part of the alias.
   * @return {boolean}
   */
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
  }
```

**File:** rest/middleware/requestHandler.js (L1-30)
```javascript
// SPDX-License-Identifier: Apache-2.0

import httpContext from 'express-http-context';
import qs from 'qs';

import config from '../config';
import {httpStatusCodes, requestIdLabel, requestStartTime} from '../constants';
import {lowerCaseQueryValue, randomString} from '../utils';

const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};

const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};

const requestLogger = async (req, res) => {
  const requestId = await randomString(8);
  httpContext.set(requestIdLabel, requestId);

  // set default http OK code for reference
  res.locals.statusCode = httpStatusCodes.OK.code;
  res.locals[requestStartTime] = Date.now();
};

```

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
```

**File:** rest/service/tokenService.js (L12-14)
```javascript
const tokenCache = new quickLru({
  maxSize: config.cache.token.maxSize,
});
```
