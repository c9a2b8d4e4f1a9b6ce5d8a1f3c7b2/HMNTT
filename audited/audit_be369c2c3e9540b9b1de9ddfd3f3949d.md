### Title
Unauthenticated EVM Address Lookup in `/api/v1/balances` Exhausts DB Connection Pool (DoS)

### Summary
The `parseAccountIdQueryParam()` function in `rest/balances.js` unconditionally issues an async `EntityService.getEncodedId()` database query for every request that supplies a valid EVM address as `account.id`. Because the REST API has no rate-limiting middleware and the default connection pool is only 10 connections, an unprivileged attacker sending concurrent requests can saturate the pool and deny service to all other users.

### Finding Description

**Exact code path:**

`getBalances()` in `rest/balances.js` (lines 87–88) calls the local `parseAccountIdQueryParam()` and immediately awaits all returned promises:

```js
const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
const accountParams = await Promise.all(accountParamsPromise);
``` [1](#0-0) 

Inside `parseAccountIdQueryParam()` (lines 320–357), when the supplied value passes `EntityId.isValidEvmAddress()`, it calls `EntityService.getEncodedId(value, false)` — an async function — and stores the returned **Promise** directly into the `values` array that `parseParams` returns:

```js
if (EntityId.isValidEvmAddress(value, EvmAddressType.NO_SHARD_REALM) && ++evmAliasAddressCount === 1) {
  return EntityService.getEncodedId(value, false);   // returns a Promise
}
``` [2](#0-1) 

`EntityService.getEncodedId()` resolves by calling `getEntityIdFromEvmAddress()`, which executes a real SQL query against the database:

```js
const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
``` [3](#0-2) 

The query is:
```sql
select id from entity where deleted <> true and evm_address = $1
``` [4](#0-3) 

**No caching:** `EntityService.getEncodedId()` has no result cache. The `entityId.js` LRU cache only caches parsed `EntityId` objects (string → struct), not the DB lookup result. [5](#0-4) 

**No REST API rate limiting:** `rest/server.js` registers only `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, and optional metrics/cache middleware — no rate-limit or in-flight-request throttle. [6](#0-5) 

**Tiny default pool:** The default `maxConnections` is **10**. [7](#0-6) 

**The `evmAliasAddressCount` guard** only prevents more than one EVM address *within a single request*; it does not limit across concurrent requests. [8](#0-7) 

### Impact Explanation

With a pool of 10 connections and no rate limiting, an attacker sending ~10–20 concurrent `GET /api/v1/balances?account.id=<valid_evm_address>` requests can hold all pool connections in the `await Promise.all(accountParamsPromise)` phase. Subsequent requests from any user queue behind the `connectionTimeoutMillis` (default 20 s) deadline. Once the queue depth exceeds what the pool can drain, new requests receive connection-timeout errors, effectively taking the `/api/v1/balances` endpoint (and any other endpoint sharing the same pool) offline for legitimate users. This is a non-network-based DoS requiring no authentication.

### Likelihood Explanation

The attack requires only an HTTP client and knowledge of any 40-hex-character string (a valid EVM address format — it need not map to a real entity; `requireResult=false` means the query runs and returns null without error). It is trivially scriptable, repeatable, and requires no credentials or special network position.

### Recommendation

1. **Cache the EVM-address-to-entity-id lookup** in `EntityService.getEncodedId()` / `getEntityIdFromEvmAddress()` with a short TTL (e.g., 30–60 s) so repeated lookups for the same address do not hit the DB.
2. **Add an in-flight request limiter** (e.g., `express-rate-limit` or a semaphore) to the REST API, specifically gating requests that trigger async DB lookups during parameter parsing.
3. **Increase `maxConnections`** to a value appropriate for the expected concurrency, or use a connection-pool proxy (PgBouncer) in front of the REST service.
4. **Move the EVM address DB lookup out of parameter parsing** and into the main query handler after basic validation, so it can be guarded by existing middleware.

### Proof of Concept

```bash
# Send 20 concurrent requests, each triggering one EVM-address DB lookup
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/balances?account.id=0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" &
done
wait

# Observe: legitimate requests to /api/v1/balances (or other endpoints sharing the pool)
# begin returning 500 / connection-timeout errors while the attack is in flight.
```

Preconditions: none — no authentication, no special network access required.  
Trigger: any 40-hex-character string (with or without `0x` prefix) as `account.id`.  
Result: DB connection pool exhausted; service degraded or unavailable for all users.

### Citations

**File:** rest/balances.js (L87-88)
```javascript
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
```

**File:** rest/balances.js (L328-339)
```javascript
      if (EntityId.isValidEvmAddress(value, EvmAddressType.NO_SHARD_REALM) && ++evmAliasAddressCount === 1) {
        return EntityService.getEncodedId(value, false);
      }
      if (AccountAlias.isValid(value, true) && ++evmAliasAddressCount === 1) {
        return EntityService.getAccountIdFromAlias(AccountAlias.fromString(value), false);
      }

      if (evmAliasAddressCount > 1) {
        throw new InvalidArgumentError({
          message: `Invalid parameter: ${constants.filterKeys.ACCOUNT_ID}`,
          detail: `Only one EVM address or alias is allowed.`,
        });
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L91-91)
```javascript
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/entityId.js (L301-304)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});
```

**File:** rest/server.js (L67-99)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
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

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```
