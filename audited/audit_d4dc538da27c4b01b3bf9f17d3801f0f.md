### Title
Unauthenticated Alias-Based Database Exhaustion via Uncached `entityFromAliasQuery` in `getEncodedId()`

### Summary
The REST Node.js service's `getEncodedId()` function in `rest/service/entityService.js` unconditionally executes a live database query for every request containing a syntactically valid but non-existent account alias. Because there is no in-process cache for alias-to-entity lookups and no request-rate limiting in the REST service, an unprivileged attacker can sustain arbitrarily high database load by flooding the endpoint with unique valid-format aliases, causing service degradation or denial of service.

### Finding Description
**Code path:**

`GET /api/v1/accounts/:idOrAliasOrEvmAddress` → `accounts.js:399` calls `EntityService.getEncodedId(req.params[...])` → `entityService.js:125` checks `AccountAlias.isValid(entityIdString)` → if true, calls `getAccountIdFromAlias()` (line 126) → `getAccountFromAlias()` (line 43) → `super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias])` → `baseService.js:56`: `this.pool().queryQuietly(query, params)` — a direct, uncached database round-trip.

**`entityFromAliasQuery`** (lines 17–20):
```sql
select id from entity
where coalesce(deleted, false) <> true
  and alias = $1
```

**`AccountAlias.isValid()`** (accountAlias.js line 41–44) only validates format via regex `/^(\d{1,5}\.){0,2}[A-Z2-7]+$/`. Any uppercase base32 string passes, regardless of whether a matching entity exists.

**`BaseService.getRows()`** (baseService.js lines 55–57) has zero caching — it calls the pool directly every time.

**Root cause / failed assumption:** The code assumes alias lookups are cheap or infrequent. There is no memoization, no negative-result cache, and no request-rate limiter in the REST Node.js service (the rate limiter found in `web3/ThrottleConfiguration.java` applies only to the separate EVM/web3 module, not to the REST service).

The response-level cache (`responseCacheHandler.js`) only helps for repeated identical URLs. An attacker using a different unique alias per request (trivially generated from the base32 alphabet A–Z, 2–7) bypasses it entirely.

### Impact Explanation
Each crafted request causes one full table scan / index lookup on the `entity` table. At scale (thousands of requests per second from a single client or botnet), this saturates the database connection pool and query executor, degrading or denying service for all legitimate users. The `entity` table is central to nearly every API endpoint, so contention here has broad blast radius. No authentication or privilege is required.

### Likelihood Explanation
The attack requires zero credentials, zero on-chain state, and only knowledge of the public REST API spec (documented in `rest/api/v1/openapi.yml`). Valid alias strings are trivially generated: any string matching `[A-Z2-7]+` of sufficient length (e.g., `AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA`) passes validation. A single attacker with a modest HTTP client can sustain thousands of unique-alias requests per second. The absence of IP-based rate limiting in the REST service makes this repeatable indefinitely.

### Recommendation
1. **Add a negative-result cache** for alias lookups (e.g., a bounded TTL cache keyed on the decoded alias bytes). Cache both hits and misses. The importer's `EntityIdServiceImpl` already demonstrates this pattern with `cacheLookup()`.
2. **Add request-rate limiting** to the REST Node.js service (e.g., via `express-rate-limit` or an API gateway), scoped per IP or per client.
3. **Optionally**, add a minimum alias length check before issuing the DB query, since very short aliases are unlikely to be valid and can be rejected cheaply.

### Proof of Concept
```bash
# Generate unique valid aliases and flood the endpoint
python3 -c "
import itertools, string, requests, threading

chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
base_url = 'http://<mirror-node-rest>:5551/api/v1/accounts/'

def send(alias):
    requests.get(base_url + alias, timeout=5)

# Each alias is unique and syntactically valid; each triggers a DB query
aliases = (''.join(c) for c in itertools.product(chars, repeat=8))
threads = [threading.Thread(target=send, args=(a,)) for a in itertools.islice(aliases, 10000)]
for t in threads: t.start()
for t in threads: t.join()
"
```

Each request hits `entityFromAliasQuery` with a unique alias, producing 10,000 uncached DB round-trips. Scaling this across multiple clients or in a loop sustains the load indefinitely. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rest/accountAlias.js (L41-44)
```javascript
  static isValid(accountAlias, noShardRealm = false) {
    const regex = noShardRealm ? noShardRealmAccountAliasRegex : accountAliasRegex;
    return typeof accountAlias === 'string' && regex.test(accountAlias);
  }
```
