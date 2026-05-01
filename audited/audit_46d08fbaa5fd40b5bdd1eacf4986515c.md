### Title
Unauthenticated DB Query Flood via Non-Existent shard.realm.num Account IDs — No Rate Limiting or Existence Check

### Summary
The `getAccountCryptoAllowances()` handler in `cryptoAllowanceController.js` resolves a `shard.realm.num`-format account ID directly to an encoded integer without any database existence check, then unconditionally executes a `SELECT` against the `crypto_allowance` table. Because no rate limiting exists anywhere in the REST server middleware stack, an unauthenticated attacker can flood the endpoint with syntactically valid but non-existent account IDs (e.g., `0.0.1` through `0.0.999999999`), each generating a distinct DB query, exhausting the connection pool and degrading service.

### Finding Description

**Code path:**

1. `rest/controllers/cryptoAllowanceController.js` line 77 — `EntityService.getEncodedId()` is called with the raw path parameter. [1](#0-0) 

2. `rest/service/entityService.js` lines 120–123 — when the input matches `EntityId.isValidEntityId()` (i.e., `shard.realm.num` format) **and** `evmAddress === null`, the function returns `entityId.getEncodedId()` immediately — **no DB existence check is performed**. [2](#0-1) 

   The `isValidAccount()` helper (line 60–63) that would perform an existence check against the `entity` table is **never called** in this flow. [3](#0-2) 

3. Back in the controller (line 80), `CryptoAllowanceService.getAccountCryptoAllowances()` is called unconditionally with the encoded ID. [4](#0-3) 

4. `rest/service/cryptoAllowanceService.js` lines 13–16 — a `SELECT * FROM crypto_allowance WHERE owner = $1 AND amount > 0 ORDER BY spender LIMIT $2` query is executed against the DB for every request, regardless of whether the account exists. [5](#0-4) 

**Why existing checks fail:**

- **No rate limiting**: A grep across all `rest/**/*.js` files finds zero rate-limiting or throttling middleware. `rest/server.js` registers only `cors`, `compression`, `httpContext`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler`, and `responseHandler` — none of which limit request rate. [6](#0-5) 

- **Response cache is optional and bypassable**: `responseCacheCheckHandler` is only active when both `config.cache.response.enabled` and `config.redis.enabled` are true (line 54). Even when enabled, the cache key is the MD5 of `req.originalUrl` (line 152 of `responseCacheHandler.js`), so each distinct account ID (e.g., `0.0.1`, `0.0.2`, …) produces a unique cache key and a fresh DB query. [7](#0-6) [8](#0-7) 

- **DB pool is finite**: `rest/config.js` parses `db.pool.maxConnections` (line 139–147). Flooding saturates this pool, blocking legitimate queries. [9](#0-8) 

### Impact Explanation
An attacker can exhaust the PostgreSQL connection pool by sending a high volume of GET requests to `/api/v1/accounts/0.0.<N>/allowances/crypto` with incrementing or random values of `<N>`. Each request causes one DB query with zero result rows but real I/O and connection-slot consumption. At saturation, all DB-dependent endpoints (accounts, transactions, tokens, etc.) become unavailable — a full application-layer DoS with no network amplification required.

### Likelihood Explanation
The exploit requires no credentials, no special knowledge, and no complex tooling — only the ability to send HTTP GET requests. The `shard.realm.num` format is publicly documented. A single machine with a modest HTTP client (e.g., `wrk`, `ab`, or a simple script) can generate thousands of requests per second. The attack is repeatable indefinitely and leaves no persistent state to clean up.

### Recommendation
Apply at least two mitigations in combination:

1. **Add rate limiting middleware** (e.g., `express-rate-limit`) globally in `rest/server.js` before route handlers, keyed on client IP, with a per-second or per-minute cap.
2. **Add an entity existence check** for `shard.realm.num` IDs before executing the allowance query — call `EntityService.isValidAccount(accountId)` after `getEncodedId()` and return HTTP 404 immediately if the account does not exist. This short-circuits the `crypto_allowance` table query for non-existent accounts and also makes the 404 response cacheable.

### Proof of Concept

```bash
# Flood with syntactically valid but non-existent account IDs
# Each request hits the DB; no auth required
for i in $(seq 100000000 100010000); do
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.$i/allowances/crypto" &
done
wait
```

Each request passes format validation, skips the entity existence check, and executes a `SELECT` against `crypto_allowance`. With sufficient concurrency the DB connection pool is exhausted and all API endpoints return errors.

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-80)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
    const {conditions, params, order, limit} = this.extractCryptoAllowancesQuery(filters, accountId);
    const allowances = await CryptoAllowanceService.getAccountCryptoAllowances(conditions, params, order, limit);
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/entityService.js (L120-124)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/service/cryptoAllowanceService.js (L13-16)
```javascript
  async getAccountCryptoAllowances(conditions, initParams, order, limit) {
    const {query, params} = this.getAccountAllowancesQuery(conditions, initParams, order, limit);
    const rows = await super.getRows(query, params);
    return rows.map((ca) => new CryptoAllowance(ca));
```

**File:** rest/server.js (L54-98)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
const openApiValidatorEnabled = config.openapi.validation.enabled;

app.disable('x-powered-by');
app.set('trust proxy', true);
app.set('port', port);
app.set('query parser', requestQueryParser);

serveSwaggerDocs(app);
if (openApiValidatorEnabled || isTestEnv()) {
  await openApiValidator(app);
}

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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/config.js (L138-148)
```javascript
  const {pool} = getConfig().db;
  const configKeys = ['connectionTimeout', 'maxConnections', 'statementTimeout'];
  configKeys.forEach((configKey) => {
    const value = pool[configKey];
    const parsed = parseInt(value, 10);
    if (Number.isNaN(parsed) || parsed <= 0) {
      throw new InvalidConfigError(`invalid value set for db.pool.${configKey}: ${value}`);
    }
    pool[configKey] = parsed;
  });
}
```
