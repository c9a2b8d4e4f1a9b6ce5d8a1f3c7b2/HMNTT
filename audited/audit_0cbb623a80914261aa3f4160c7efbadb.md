### Title
Unauthenticated EVM Address Lookup Enables DB Connection Pool Exhaustion DoS

### Summary
The `getAccountCryptoAllowances()` handler in `cryptoAllowanceController.js` unconditionally triggers a database query for every request containing a valid-format EVM address path parameter, with no rate limiting at the application layer. An unprivileged attacker can flood this endpoint with thousands of concurrent requests using syntactically valid but non-existent EVM addresses, exhausting the finite DB connection pool and causing mirror node REST instances to stop serving requests.

### Finding Description
**Exact code path:**

In `rest/controllers/cryptoAllowanceController.js` line 77, `getAccountCryptoAllowances()` calls:
```js
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
```

In `rest/service/entityService.js` lines 118–124, `getEncodedId()` detects a valid EVM address and routes to:
```js
: await this.getEntityIdFromEvmAddress(entityId, requireResult);
```

In `rest/service/entityService.js` lines 90–104, `getEntityIdFromEvmAddress()` unconditionally executes:
```sql
SELECT id FROM entity WHERE deleted <> true AND evm_address = $1
```
via `this.getRows(...)` → `this.pool().queryQuietly(...)` (see `rest/service/baseService.js` lines 55–57).

**Root cause:** Every inbound request with a syntactically valid EVM address (40 hex chars) triggers a live DB query. There is no caching of negative (not-found) results, no per-IP throttle, and no application-level rate limiter. Inspection of `rest/server.js` (lines 68–144) confirms the middleware stack contains only: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — **no rate-limiting middleware**.

**Why existing checks fail:**
- `maxConnections` (parsed in `rest/config.js` lines 137–148) caps the pool size but does not prevent it from being fully consumed.
- `connectionTimeout` causes queued requests to fail after a timeout, but during that window all pool slots remain occupied.
- `statementTimeout` limits individual query duration, but the query itself (`SELECT` on an indexed column) completes quickly — the bottleneck is pool slot availability under concurrent load, not per-query duration.
- `authHandler` enforces credentials only for privileged users; the allowances endpoint is publicly accessible without authentication.
- Infrastructure-level Traefik middleware (`charts/hedera-mirror-rest/templates/middleware.yaml`) may provide rate limiting, but this is deployment-dependent and not enforced at the application layer.

### Impact Explanation
When the DB connection pool is fully occupied, new requests queue until `connectionTimeout` elapses, then fail with errors. Under sustained flood conditions, the Node.js process accumulates thousands of pending async operations waiting on pool slots, consuming heap memory and degrading event-loop throughput. This causes the REST instance to return errors for all DB-dependent endpoints — not just the allowances route — effectively taking the instance out of service. Targeting multiple instances simultaneously (trivial with a distributed client) can take down 30%+ of the REST tier.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only knowledge of the public API schema (EVM addresses are 40-character hex strings, trivially generated). The endpoint is documented in the OpenAPI spec served by the node itself. The attack is fully automatable, repeatable, and resumable. No exploit code, special tooling, or insider access is needed — standard HTTP load tools (e.g., `wrk`, `hey`, `ab`) suffice.

### Recommendation
1. **Add application-level rate limiting** (e.g., `express-rate-limit`) scoped per IP on all public endpoints, with a tighter limit on endpoints that trigger DB lookups.
2. **Cache negative EVM address lookups** (short TTL, e.g., 30s) to avoid repeated DB hits for the same non-existent address.
3. **Add a concurrency limiter** (e.g., `p-limit` or a semaphore) around `getEntityIdFromEvmAddress()` to cap simultaneous in-flight DB queries regardless of request volume.
4. **Enforce infrastructure-level rate limiting** (Traefik `RateLimit` middleware) as a mandatory deployment requirement, not an optional chart value.

### Proof of Concept
```bash
# Generate 5000 concurrent requests with random valid-format EVM addresses
# (no authentication required)
for i in $(seq 1 5000); do
  ADDR=$(openssl rand -hex 20)
  curl -s "https://<mirror-node-host>/api/v1/accounts/${ADDR}/allowances/crypto" &
done
wait

# Observe: subsequent legitimate requests to any DB-backed endpoint
# return 500/503 errors or time out, confirming pool exhaustion.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/controllers/cryptoAllowanceController.js (L76-78)
```javascript
  getAccountCryptoAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedCryptoAllowanceParameters);
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

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/config.js (L137-148)
```javascript
function parseDbPoolConfig() {
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

**File:** rest/server.js (L68-98)
```javascript
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
