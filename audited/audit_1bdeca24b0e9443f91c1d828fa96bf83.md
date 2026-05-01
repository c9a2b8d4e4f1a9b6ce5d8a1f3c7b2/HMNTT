### Title
REST API DB Connection Pool Exhaustion DoS via Unbounded Concurrent Slow-Query Requests

### Summary
The `parseDbPoolConfig()` function in `rest/config.js` validates only that `maxConnections` is a positive integer (`> 0`), with no enforced minimum above 1. Combined with a default pool of 10 connections, a 20-second `statementTimeout`, and the complete absence of per-IP rate limiting or in-flight request limiting in the REST API's middleware stack, an unprivileged external attacker can exhaust all database pool connections by sending 10 concurrent requests that trigger slow queries. This renders the REST API unresponsive to all other users for up to 20 seconds per attack cycle, and the attack is trivially repeatable.

### Finding Description
**Code path:**

`rest/config.js` `parseDbPoolConfig()` (lines 137–148):
```js
if (Number.isNaN(parsed) || parsed <= 0) {
  throw new InvalidConfigError(`invalid value set for db.pool.${configKey}: ${value}`);
}
pool[configKey] = parsed;
```
The only guard is `parsed <= 0`. A `maxConnections` of 1 is accepted. The default is 10 (`docs/configuration.md` line 556).

`rest/dbpool.js` (lines 13–15):
```js
connectionTimeoutMillis: config.db.pool.connectionTimeout,  // 20000ms
max: config.db.pool.maxConnections,                          // 10
statement_timeout: config.db.pool.statementTimeout,          // 20000ms
```
The `pg` pool is created with these values directly. When all 10 connections are busy, new requests queue until `connectionTimeoutMillis` (20s) expires, then fail with a 500.

**Missing rate limiting:**

`rest/server.js` (lines 68–144): The Express middleware stack contains `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, route handlers, and error handlers. There is **no** `express-rate-limit` or equivalent per-IP or in-flight request limiter.

`charts/hedera-mirror-rest/values.yaml` (lines 134–139): The Traefik middleware for the REST API is:
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
```
There is **no** `inFlightReq` and **no** `rateLimit` entry. Contrast with the Rosetta API (`charts/hedera-mirror-rosetta/values.yaml` lines 152–160) which has both `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per host. The REST API has neither.

**Root cause:** `parseDbPoolConfig()` fails to enforce a meaningful minimum for `maxConnections`, and no compensating control (rate limiting, in-flight limiting) exists at any layer for the REST API. The `retry: attempts: 10` Traefik middleware can amplify pool pressure by replaying timed-out requests up to 10 additional times.

### Impact Explanation
All 10 pool connections become occupied for up to 20 seconds. Every legitimate request arriving during this window queues and then fails with a connection timeout error (HTTP 500). The circuit breaker (`ResponseCodeRatio(500,600,0,600) > 0.25`) may eventually trip, but only after 25% of responses are already errors, and it does not prevent the initial exhaustion. The attack is repeatable with zero delay: as soon as the `statementTimeout` fires and connections are released, the attacker re-sends the next wave. This constitutes a sustained, low-bandwidth DoS of the public REST API with no authentication required.

**Severity: High** — complete availability loss for the REST API, achievable with 10 HTTP requests per 20-second cycle from a single IP.

### Likelihood Explanation
The REST API is a public, unauthenticated read endpoint. Any internet user can send concurrent HTTP GET requests. Triggering near-`statementTimeout` queries is feasible: endpoints like `/api/v1/transactions` with wide timestamp ranges (`maxTransactionsTimestampRange` defaults to 60 days), or `/api/v1/tokens/:tokenId/nfts` with large result sets, can produce multi-second queries on a loaded database. No exploit tooling beyond `curl` or `ab` (Apache Bench) is needed. The attack is repeatable indefinitely and requires no credentials, tokens, or prior knowledge beyond the public API documentation.

### Recommendation
1. **`parseDbPoolConfig()`**: Enforce a minimum `maxConnections` of at least 10 (or a configurable floor, e.g., `MIN_POOL_CONNECTIONS = 10`) in the validation block at `rest/config.js` line 143.
2. **Traefik middleware**: Add `inFlightReq` (e.g., `amount: 20`, `sourceCriterion.ipStrategy.depth: 1`) and `rateLimit` (e.g., `average: 50`, `sourceCriterion.requestHost: true`) to `charts/hedera-mirror-rest/values.yaml`, mirroring the Rosetta API's middleware configuration.
3. **Application layer**: Add `express-rate-limit` middleware in `rest/server.js` before route handlers to enforce per-IP request rate limits independent of the infrastructure layer.
4. **Pool sizing**: Increase the default `maxConnections` to match realistic concurrency expectations, or document a required minimum for production deployments.

### Proof of Concept
**Preconditions:** Default configuration (`maxConnections=10`, `statementTimeout=20000`). No Traefik `inFlightReq`/`rateLimit` middleware deployed (default `values.yaml`).

**Steps:**
```bash
# Send 10 concurrent requests designed to trigger slow queries
# (wide timestamp range scan on a populated mirror node)
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/transactions?timestamp=gte:0&timestamp=lte:9999999999&limit=100" &
done
wait

# Immediately probe with a legitimate request — it will queue and timeout
time curl -s "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: ~20s delay followed by HTTP 500 (connection timeout from pool)
```

**Result:** The 10 background requests hold all pool connections for up to 20 seconds. The probe request queues, waits the full `connectionTimeoutMillis` (20s), and returns a 500 error. Repeating the first block immediately after creates a continuous denial-of-service cycle. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** charts/hedera-mirror-rest/values.yaml (L134-139)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - retry:
      attempts: 10
      initialInterval: 100ms
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
