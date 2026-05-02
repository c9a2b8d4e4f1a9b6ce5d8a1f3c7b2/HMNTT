### Title
Unauthenticated Alias-Miss DoS via Double DB Round-Trip Exhausts Connection Pool in `getBalances()`

### Summary
Any unauthenticated caller can supply a syntactically valid but non-existent account alias in `account.id=eq:<alias>` to `/api/v1/balances`. This causes `getBalances()` to unconditionally execute two sequential DB queries per request — one alias-resolution lookup that returns `null`, and a second main balance query with a `null` parameter — with no early-exit, no caching, and no rate limiting. Flooding this endpoint with concurrent requests exhausts the default 10-connection DB pool, starving legitimate users.

### Finding Description

**Code path — alias resolution:**

In `rest/balances.js`, `parseAccountIdQueryParam` (lines 320–357) handles the `account.id` filter. When the value passes `AccountAlias.isValid(value, true)`, it calls:

```js
return EntityService.getAccountIdFromAlias(AccountAlias.fromString(value), false);
``` [1](#0-0) 

The second argument `false` is `requireResult=false`. In `rest/service/entityService.js`, `getAccountIdFromAlias` (lines 71–81) calls `getAccountFromAlias`, which issues a live DB query:

```js
const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
``` [2](#0-1) 

When no row is found, `getAccountFromAlias` returns `null`, and `getAccountIdFromAlias` propagates `null` (no exception because `requireResult=false`): [3](#0-2) 

**Code path — missing null guard in `getBalances()`:**

Back in `getBalances()`, the resolved promise is awaited:

```js
const accountParams = await Promise.all(accountParamsPromise);
``` [4](#0-3) 

There is **no null check** on `accountParams` after this line. The code unconditionally proceeds to build and execute the main SQL query with `null` as the bound parameter: [5](#0-4) 

In PostgreSQL, `ab.account_id = NULL` evaluates to `NULL` (never `true`), so the query returns zero rows — a fully wasted second DB round-trip.

**No caching of alias lookups:**

`BaseService.getRows()` calls `pool.queryQuietly()` directly with no cache layer: [6](#0-5) 

The `entityId` cache referenced in configuration belongs to the Java importer module, not this Node.js service.

**No rate limiting on the REST API:**

`server.js` registers no rate-limiting middleware for the `/balances` route — only `authHandler`, optional `metricsHandler`, and optional `responseCacheCheckHandler`: [7](#0-6) 

The throttling found (`ThrottleManagerImpl`, `ThrottleConfiguration`) applies exclusively to the `web3` Java service for contract calls, not to the Node.js REST API.

**DB pool size:**

The default maximum DB connections is **10**: [8](#0-7) 

Pool configuration in `dbpool.js`: [9](#0-8) 

### Impact Explanation

Each request with a non-existent alias consumes two sequential DB connections (alias lookup + balance query). With a pool capped at 10 connections and a `connectionTimeoutMillis` of 20,000 ms, an attacker sending ~10 concurrent requests keeps the pool saturated. Legitimate requests queue and eventually time out with a connection-pool error, effectively taking the `/api/v1/balances` endpoint (and any other endpoint sharing the same pool) offline for real users. No on-chain state or user funds are affected; this is a mirror-node availability (griefing) impact.

### Likelihood Explanation

The endpoint is public and unauthenticated. The alias format is documented in the OpenAPI spec. A valid-format alias string (e.g., a base32-encoded public key) is trivially generated. No special privileges, tokens, or accounts are required. The attack is trivially scriptable with any HTTP client (`curl`, `ab`, `wrk`) and is repeatable indefinitely. The attacker incurs zero cost.

### Recommendation

1. **Early-exit on null alias resolution**: After `await Promise.all(accountParamsPromise)`, check whether any resolved value is `null` and return an empty result immediately, skipping the second DB query.
2. **Add rate limiting**: Apply a per-IP rate limiter (e.g., `express-rate-limit`) to the REST API, specifically to alias/EVM-address lookup paths.
3. **Cache negative alias lookups**: Cache `null` results from `getAccountIdFromAlias` with a short TTL (e.g., 30 s) to prevent repeated DB hits for the same non-existent alias.
4. **Increase pool size or add connection-level back-pressure**: Tune `hiero.mirror.rest.db.pool.maxConnections` and add request queuing/shedding before DB access.

### Proof of Concept

```bash
# Generate a syntactically valid base32 alias that does not exist on-chain
ALIAS="AAAQEAYEAUDAOCAJCAIREEYUCULBOGAZ"

# Flood with 20 concurrent requests (2x the default pool size)
for i in $(seq 1 20); do
  curl -s "http://<mirror-node-host>:5551/api/v1/balances?account.id=eq:${ALIAS}" &
done
wait

# Legitimate request now times out or receives a 500 due to pool exhaustion
curl -v "http://<mirror-node-host>:5551/api/v1/balances"
```

Each of the 20 concurrent attacker requests triggers:
1. `SELECT id FROM entity WHERE alias = $1` → 0 rows → `null`
2. `SELECT ... FROM entity_balance ab WHERE ab.account_id = NULL ...` → 0 rows

With 10 max connections, legitimate requests queue for up to 20 s before timing out.

### Citations

**File:** rest/balances.js (L87-88)
```javascript
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
```

**File:** rest/balances.js (L152-154)
```javascript
  const pgSqlQuery = utils.convertMySqlStyleQueryToPostgres(sqlQuery);
  const result = await pool.queryQuietly(pgSqlQuery, sqlParams);
  res.locals[constants.responseDataLabel] = formatBalancesResult(req, result, limit, order);
```

**File:** rest/balances.js (L331-332)
```javascript
      if (AccountAlias.isValid(value, true) && ++evmAliasAddressCount === 1) {
        return EntityService.getAccountIdFromAlias(AccountAlias.fromString(value), false);
```

**File:** rest/service/entityService.js (L42-43)
```javascript
  async getAccountFromAlias(accountAlias) {
    const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
```

**File:** rest/service/entityService.js (L71-78)
```javascript
  async getAccountIdFromAlias(accountAlias, requireResult = true) {
    const entity = await this.getAccountFromAlias(accountAlias);
    if (isNil(entity)) {
      if (requireResult) {
        throw new NotFoundError(EntityService.missingAccountAlias);
      }
      return null;
    }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/server.js (L85-98)
```javascript
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

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
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
