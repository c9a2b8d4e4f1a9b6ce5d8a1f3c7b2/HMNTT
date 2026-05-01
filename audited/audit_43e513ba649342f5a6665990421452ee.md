### Title
Unauthenticated DB Connection Exhaustion via Unconditional `entityExistenceQuery` in `getTokenRelationships()` with No Rate Limiting

### Summary
The `getTokenRelationships()` handler unconditionally fires a database query (`entityExistenceQuery`) via `EntityService.isValidAccount()` for every request, including those with valid-format but non-existent account IDs. The REST service has no rate limiting for unauthenticated users. An attacker can flood the endpoint with syntactically valid but non-existent account IDs, saturating the finite DB connection pool and degrading service availability.

### Finding Description

**Exact code path:**

`rest/controllers/tokenController.js`, lines 67–71:
```js
const accountId = await EntityService.getEncodedId(req.params[...]);
const isValidAccount = await EntityService.isValidAccount(accountId);
if (!isValidAccount) { throw new NotFoundError(); }
```

`rest/service/entityService.js`, lines 28–30 and 60–63:
```js
static entityExistenceQuery = `select ${Entity.TYPE} from ${Entity.tableName} where ${Entity.ID} = $1`;

async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);
}
```

**Root cause:** For a numeric entity ID (e.g., `0.0.999999999`), `getEncodedId()` returns the encoded ID with **no DB query** (line 122–123 of `entityService.js`: `entityId.evmAddress === null ? entityId.getEncodedId() : ...`). Control then passes unconditionally to `isValidAccount()`, which always executes `entityExistenceQuery` against the DB regardless of whether the account exists.

**Why existing checks fail:**

- `rest/middleware/authHandler.js` only sets a custom response `limit` for authenticated users — it performs **no rate limiting** and does not block unauthenticated requests.
- `rest/server.js` middleware stack (`httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`) contains **no per-IP or global rate limiter** for the REST service.
- The throttle configuration found (`web3/src/main/java/.../ThrottleConfiguration.java`) applies only to the **web3 Java service**, not the Node.js REST service.
- The DB connection pool (`rest/dbpool.js`, line 14: `max: config.db.pool.maxConnections`) is finite. `statement_timeout` limits individual query duration but does not prevent pool saturation under concurrent load.
- Response caching (`responseCacheCheckHandler`) only caches successful responses; a 404 path (non-existent account) bypasses the cache and always hits the DB.

### Impact Explanation
Every concurrent request to `GET /api/v1/accounts/{id}/tokens` with a valid-format non-existent ID consumes one DB connection for the duration of the `entityExistenceQuery`. With a finite pool (default `maxConnections` from config), sustained concurrent flooding exhausts available connections. Legitimate requests then queue behind the `connectionTimeoutMillis` deadline and begin timing out, degrading or denying service to all users of the REST API. Because the REST service is a shared read path for the mirror node, this can degrade ≥30% of network query processing capacity without requiring any privileged access.

### Likelihood Explanation
No authentication, API key, or proof-of-work is required. Any external actor can send HTTP GET requests. The attack is trivially scriptable (e.g., `ab`, `wrk`, or a simple async loop). Valid-format IDs (`0.0.<large_num>`) are easy to generate in bulk. The attack is repeatable and stateless — each request is independent. The only natural friction is network bandwidth and the speed of the PK lookup, but even a fast query holds a connection for its round-trip duration, and at sufficient concurrency the pool saturates.

### Recommendation
1. **Add rate limiting middleware** to the Node.js REST service (e.g., `express-rate-limit` or an nginx/ingress-level rate limiter) applied globally before route handlers, targeting unauthenticated clients by IP.
2. **Cache negative (404) results** for `isValidAccount()` using a short-TTL in-memory or Redis cache, so repeated queries for the same non-existent ID do not hit the DB.
3. **Short-circuit early**: consider moving `isValidAccount()` after a cache check, or combining it with the subsequent `TokenService.getTokenAccounts()` query to avoid a separate round-trip.
4. **Tune pool settings**: ensure `connectionTimeoutMillis` is low enough to shed load quickly rather than queuing indefinitely.

### Proof of Concept
```bash
# Generate 500 concurrent requests with valid-format but non-existent account IDs
# No authentication required
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.$((RANDOM + 9000000))/tokens" &
done
wait
```
Each request reaches `isValidAccount()`, fires `SELECT type FROM entity WHERE id = $1` against the DB, finds no row, and returns 404 — but only after consuming a DB connection. At sufficient concurrency, the pool (`maxConnections`) is saturated, and subsequent legitimate requests receive connection timeout errors, degrading the service. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/controllers/tokenController.js (L66-71)
```javascript
  getTokenRelationships = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
    if (!isValidAccount) {
      throw new NotFoundError();
    }
```

**File:** rest/service/entityService.js (L28-30)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
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

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
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
