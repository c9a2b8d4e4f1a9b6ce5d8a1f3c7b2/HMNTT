### Title
Unauthenticated EVM Address Flood Causes Database Connection Pool Exhaustion via Uncached Miss Queries

### Summary
`getEntityIdFromEvmAddress()` in `rest/service/entityService.js` executes a live database query for every EVM address lookup with no negative-result caching. The response cache layer explicitly skips caching non-2xx responses, and no rate-limiting middleware exists in the REST server stack. An unauthenticated attacker flooding the API with unique, non-existent 40-hex-character EVM addresses can exhaust the database connection pool, causing sustained degradation for all users.

### Finding Description

**Exact code path:**

`entityFromEvmAddressQuery` is defined at lines 22–25 of `rest/service/entityService.js`:
```sql
SELECT id FROM entity
WHERE deleted <> true AND evm_address = $1
``` [1](#0-0) 

`getEntityIdFromEvmAddress()` (lines 90–104) executes this query unconditionally on every call, with no in-process or distributed cache for miss results: [2](#0-1) 

**Root cause — response cache skips 404s:**

`responseCacheUpdateHandler` in `rest/middleware/responseCacheHandler.js` only stores responses when `httpStatusCodes.isSuccess(res.statusCode)` is true (line 95). A 404 from a non-existent EVM address is never cached: [3](#0-2) 

**Root cause — no rate limiting:**

`rest/server.js` registers only `authHandler`, `requestLogger`, `metricsHandler`, and the optional `responseCacheCheckHandler`. There is no `express-rate-limit` or equivalent middleware anywhere in the stack: [4](#0-3) 

**Index note:** A partial index `entity__evm_address` exists (`WHERE evm_address IS NOT NULL`), so each miss is an index scan rather than a full table scan: [5](#0-4) 

While each individual query is fast (O(log n) index scan), the database connection pool is finite. With no rate limiting and no miss caching, a flood of unique addresses saturates the pool, blocking legitimate queries.

**Trigger surface:** The `getEncodedId()` method (lines 118–137) calls `getEntityIdFromEvmAddress()` whenever the input is a valid EVM address string, which is reachable from multiple public endpoints including `/api/v1/accounts/:id` and contract routes: [6](#0-5) [7](#0-6) 

### Impact Explanation

An attacker exhausting the PostgreSQL connection pool causes all database-dependent API endpoints to fail or queue indefinitely — not just the EVM address lookup path. This is a non-network-based DoS: the attacker does not need to saturate bandwidth, only generate valid-format EVM address strings (trivially scriptable). All users of the mirror node REST API are affected for the duration of the attack.

### Likelihood Explanation

No authentication, no rate limiting, and no CAPTCHA are required. A single machine running a loop generating random 32-byte hex strings and issuing HTTP GET requests can sustain thousands of requests per second. The attack is repeatable indefinitely, requires no special knowledge beyond the public API format, and is undetectable until DB pool exhaustion manifests.

### Recommendation

1. **Negative-result cache:** Cache miss results (e.g., a sentinel value with a short TTL such as 5–30 seconds) in Redis for EVM address lookups. The existing Redis cache infrastructure is already present; extend `responseCacheUpdateHandler` to also cache 404 responses for EVM address routes, or add an in-service LRU miss cache inside `getEntityIdFromEvmAddress()`.
2. **Rate limiting:** Add `express-rate-limit` (or equivalent) middleware in `rest/server.js` before route handlers, keyed by IP, targeting endpoints that trigger EVM address DB lookups.
3. **Connection pool protection:** Configure a query timeout and a maximum connection wait time in the DB pool so that pool exhaustion fails fast rather than queuing indefinitely.

### Proof of Concept

```bash
# Generate and flood with unique non-existent EVM addresses
for i in $(seq 1 100000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node>/api/v1/accounts/0x${ADDR}" &
done
wait
```

Each request reaches `getEntityIdFromEvmAddress()`, executes a DB index scan, returns 404, and is not cached. With sufficient concurrency the PostgreSQL connection pool is exhausted and subsequent legitimate requests receive connection errors or time out.

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

**File:** rest/middleware/responseCacheHandler.js (L90-97)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
```

**File:** rest/server.js (L82-98)
```javascript
app.use(httpContext.middleware);
app.useExt(requestLogger);

// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/server.js (L101-103)
```javascript
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);
```

**File:** importer/src/main/resources/db/migration/v1/V1.58.6__ethereum_nonce.sql (L9-9)
```sql
create index if not exists entity__evm_address on entity (evm_address) where evm_address is not null;
```
