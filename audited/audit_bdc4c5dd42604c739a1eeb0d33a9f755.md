### Title
Unauthenticated DB Connection Pool Exhaustion via Non-Cached EVM Address Lookups in `getAccountCryptoAllowances`

### Summary
Any unauthenticated user can supply a syntactically valid, non-long-zero EVM address to the `/api/v1/accounts/:idOrAliasOrEvmAddress/allowances/crypto` endpoint. Each such request unconditionally executes a live database query (`entityFromEvmAddressQuery`) with no application-level caching or rate limiting. By flooding the endpoint with concurrent requests, an attacker can exhaust the finite DB connection pool, causing a non-network denial of service affecting all API consumers.

### Finding Description

**Exact code path:**

`getAccountCryptoAllowances()` in `rest/controllers/cryptoAllowanceController.js` line 77 calls:

```js
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
``` [1](#0-0) 

`getEncodedId()` in `rest/service/entityService.js` lines 120–124 branches on whether the parsed `EntityId` has a non-null `evmAddress` field:

```js
if (EntityId.isValidEntityId(entityIdString)) {
  const entityId = EntityId.parseString(entityIdString, {paramName});
  return entityId.evmAddress === null
    ? entityId.getEncodedId()
    : await this.getEntityIdFromEvmAddress(entityId, requireResult);
``` [2](#0-1) 

For any non-long-zero EVM address (e.g. `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`), `evmAddress` is non-null, so `getEntityIdFromEvmAddress()` is always called. That function executes a live DB query on every invocation:

```js
const rows = await this.getRows(EntityService.entityFromEvmAddressQuery,
  [Buffer.from(entityId.evmAddress, 'hex')]);
``` [3](#0-2) 

The query itself:

```sql
select id from entity where deleted <> true and evm_address = $1
``` [4](#0-3) 

**Root cause — no caching for EVM address lookups:**

The JS REST service has no in-memory or Redis cache at the service layer for EVM address resolution. The response-level Redis cache (`responseCacheHandler.js`) only stores **successful** (2xx) responses:

```js
if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
``` [5](#0-4) 

A non-existent EVM address returns HTTP 404, which is **never cached**. The attacker can reuse the same address indefinitely and every request hits the DB.

**Root cause — no rate limiting:**

The middleware stack registered in `server.js` contains: `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — no rate-limiting middleware exists at the application layer. [6](#0-5) 

**Root cause — finite DB connection pool:**

`dbpool.js` creates a pool bounded by `config.db.pool.maxConnections`. When all connections are occupied, new queries queue or time out. [7](#0-6) 

### Impact Explanation
When the DB connection pool is exhausted, every other API endpoint that requires a DB connection (transactions, balances, tokens, etc.) also fails or queues indefinitely. This is a full-service denial of service affecting all consumers of the mirror node REST API, not just the allowances endpoint. The impact is proportional to the pool size: a small pool is easier to exhaust; a large pool requires more concurrent connections from the attacker but remains achievable.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no privileged access — only the ability to send HTTP requests. A single attacker with a modest botnet or even a single machine with high concurrency (e.g., using `async` HTTP clients) can sustain the flood. The endpoint is publicly documented and the EVM address format is trivially constructable. The attack is repeatable and stateless: the attacker does not need to maintain session state.

### Recommendation
1. **Cache negative results**: Add an in-memory (or Redis) cache for EVM address → entity ID lookups, including a short-lived negative cache entry (e.g., 5–10 seconds) for addresses that resolve to 404. This eliminates repeated DB hits for the same address.
2. **Add application-level rate limiting**: Introduce a rate-limiting middleware (e.g., `express-rate-limit`) keyed on IP address, applied globally or specifically to path-parameter-driven endpoints.
3. **Limit connection acquisition**: Configure `connectionTimeoutMillis` aggressively so that pool-exhaustion conditions fail fast and return 503 rather than queuing indefinitely.
4. **Deploy infrastructure-level rate limiting**: Enforce request rate limits at the reverse proxy or API gateway layer as a defense-in-depth measure.

### Proof of Concept
```bash
# Flood with a non-existent EVM address (404 responses, never cached)
# Each request triggers entityFromEvmAddressQuery against the DB

EVM="0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
URL="http://<mirror-node-host>/api/v1/accounts/${EVM}/allowances/crypto"

# Send 500 concurrent requests
for i in $(seq 1 500); do
  curl -s -o /dev/null "$URL" &
done
wait

# Observe: other endpoints (e.g. /api/v1/transactions) begin returning
# connection timeout errors or 503s as the DB pool is exhausted.
```

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-78)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
```

**File:** rest/service/entityService.js (L22-25)
```javascript
  static entityFromEvmAddressQuery = `select ${Entity.ID}
                                      from ${Entity.tableName}
                                      where ${Entity.DELETED} <> true
                                        and ${Entity.EVM_ADDRESS} = $1`;
```

**File:** rest/service/entityService.js (L90-91)
```javascript
  async getEntityIdFromEvmAddress(entityId, requireResult = true) {
    const rows = await this.getRows(EntityService.entityFromEvmAddressQuery, [Buffer.from(entityId.evmAddress, 'hex')]);
```

**File:** rest/service/entityService.js (L120-124)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
          : await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

**File:** rest/middleware/responseCacheHandler.js (L95-95)
```javascript
  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
```

**File:** rest/server.js (L67-98)
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
