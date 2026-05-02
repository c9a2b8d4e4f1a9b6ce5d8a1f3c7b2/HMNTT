### Title
Connection Pool Exhaustion DoS via Unconstrained Concurrent Slow Queries in REST API

### Summary
The REST API's `parseDbPoolConfig()` in `rest/config.js` validates only that pool parameters are positive integers, imposing no upper bound or relationship constraint between `statementTimeout` (20,000 ms), `maxConnections` (10), and `connectionTimeout` (20,000 ms). Because the REST API has no per-IP rate limiting or concurrent-request limiting middleware, an unauthenticated attacker can saturate all 10 pool connections with slow queries for up to 20 seconds, causing every subsequent request from any user to queue for 20 seconds before failing — a sustained, rolling denial-of-service window.

### Finding Description

**Exact code path:**

`parseDbPoolConfig()` in `rest/config.js` (lines 137–148) reads the three pool parameters and validates only that each is a positive integer:

```js
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
``` [1](#0-0) 

These values are then passed directly to the `pg` pool in `rest/dbpool.js` (lines 7–16):

```js
const poolConfig = {
  connectionTimeoutMillis: config.db.pool.connectionTimeout,  // 20000
  max: config.db.pool.maxConnections,                         // 10
  statement_timeout: config.db.pool.statementTimeout,         // 20000
};
``` [2](#0-1) 

**Root cause:** `parseDbPoolConfig()` enforces no upper bound on `statementTimeout` and no relationship between `statementTimeout`, `maxConnections`, and `connectionTimeout`. The failed assumption is that the defaults are safe in the absence of any request-rate or concurrency controls.

**Exploit flow:**

1. Attacker identifies any REST endpoint that triggers a slow DB query (e.g., large timestamp-range scans on `/api/v1/transactions`, `/api/v1/accounts`, etc.).
2. Attacker sends exactly 10 concurrent HTTP requests, each triggering a query that runs for close to 20 seconds (the `statement_timeout` ceiling).
3. All 10 `pg` pool connections are held. The pool's `max=10` is exhausted.
4. Every subsequent request from any user enters the pool's internal wait queue. With `connectionTimeoutMillis=20000`, each queued request waits up to 20 seconds before receiving a connection-timeout error.
5. The attacker re-fires 10 new slow requests as soon as the previous batch times out, maintaining continuous pool exhaustion.

**Why existing checks fail:**

The REST API's middleware stack in `rest/server.js` (lines 68–144) contains: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler`, `responseHandler`, and `handleError` — **no rate limiting, no per-IP concurrency cap, no in-flight request limit**. [3](#0-2) 

The web3 API has `ThrottleManagerImpl` with per-second rate limiting, and the Rosetta Helm chart configures Traefik `inFlightReq` and `rateLimit` middleware — but neither applies to the REST API. [4](#0-3) 

### Impact Explanation
All 10 pool connections can be held for up to 20 seconds by a single attacker. During this window, every legitimate API consumer either waits 20 seconds (consuming their own HTTP client timeout budget) or receives a 500-class error. The attacker can sustain this indefinitely with minimal resources (10 concurrent HTTP connections). This constitutes a complete, unauthenticated denial-of-service against the public Mirror Node REST API — affecting all consumers globally, not just the attacker's IP.

### Likelihood Explanation
The REST API is a public, unauthenticated read API. The attacker requires: (a) network access to the API (trivially satisfied for a public node), (b) knowledge of any endpoint that produces a slow query (discoverable via the public OpenAPI spec at `/docs`), and (c) the ability to issue 10 concurrent HTTP requests (achievable with `curl`, `ab`, `wrk`, or any scripting language). No credentials, no special knowledge, and no elevated privileges are required. The attack is repeatable and automatable.

### Recommendation

1. **Add per-IP concurrent request limiting** in the REST API middleware (e.g., using `express-rate-limit` or a Traefik `inFlightReq` middleware analogous to what Rosetta uses).
2. **Reduce the effective `statementTimeout`** to a value significantly lower than `connectionTimeoutMillis` (e.g., `statementTimeout=5000`, `connectionTimeoutMillis=3000`) so that slow queries release connections quickly.
3. **Increase `maxConnections`** or deploy multiple REST API replicas behind a load balancer to dilute the impact of pool exhaustion from a single attacker.
4. **Enforce a maximum in `parseDbPoolConfig()`**: reject configurations where `statementTimeout >= connectionTimeoutMillis` or where `maxConnections` is below a safe threshold.
5. **Add a global HTTP request timeout** at the Express/Node.js layer (e.g., `server.timeout`) independent of the DB pool timeout.

### Proof of Concept

```bash
# Step 1: Identify a slow endpoint (e.g., large timestamp range scan)
ENDPOINT="http://<mirror-node-host>:5551/api/v1/transactions?timestamp=gte:0000000001.000000000&timestamp=lte:9999999999.000000000&limit=100"

# Step 2: Saturate all 10 pool connections with concurrent slow requests
for i in $(seq 1 10); do
  curl -s "$ENDPOINT" &
done

# Step 3: Immediately send an 11th request as a legitimate user
# This will hang for ~20 seconds then fail
time curl -s "$ENDPOINT"
# Expected: ~20 second delay, then connection timeout error

# Step 4: Repeat steps 2-3 in a loop to maintain the blackout
while true; do
  for i in $(seq 1 10); do curl -s "$ENDPOINT" & done
  sleep 18  # re-fire before previous batch times out
done
```

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

**File:** rest/server.js (L24-34)
```javascript
import {
  authHandler,
  handleError,
  openApiValidator,
  requestLogger,
  requestQueryParser,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
  responseHandler,
  serveSwaggerDocs,
} from './middleware';
```

**File:** rest/server.js (L68-144)
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

// accounts routes
app.getExt(`${apiPrefix}/accounts`, accounts.getAccounts);
app.getExt(`${apiPrefix}/accounts/:${constants.filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS}`, accounts.getOneAccount);
app.use(`${apiPrefix}/${AccountRoutes.resource}`, AccountRoutes.router);

// balances routes
app.getExt(`${apiPrefix}/balances`, balances.getBalances);

// contracts routes
app.use(`${apiPrefix}/${ContractRoutes.resource}`, ContractRoutes.router);

// block routes
app.use(`${apiPrefix}/${BlockRoutes.resource}`, BlockRoutes.router);

// schedules routes
app.getExt(`${apiPrefix}/schedules`, schedules.getSchedules);
app.getExt(`${apiPrefix}/schedules/:scheduleId`, schedules.getScheduleById);

// tokens routes
app.getExt(`${apiPrefix}/tokens`, tokens.getTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId`, tokens.getTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/balances`, tokens.getTokenBalances);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts`, tokens.getNftTokensRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber`, tokens.getNftTokenInfoRequest);
app.getExt(`${apiPrefix}/tokens/:tokenId/nfts/:serialNumber/transactions`, tokens.getNftTransferHistoryRequest);

// topics routes
app.getExt(`${apiPrefix}/topics/:topicId/messages`, topicmessage.getTopicMessages);
app.getExt(`${apiPrefix}/topics/:topicId/messages/:sequenceNumber`, topicmessage.getMessageByTopicAndSequenceRequest);
app.getExt(`${apiPrefix}/topics/messages/:consensusTimestamp`, topicmessage.getMessageByConsensusTimestamp);

// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);

// response data handling middleware
app.useExt(responseHandler);

// Update Cache with response
if (applicationCacheEnabled) {
  app.useExt(responseCacheUpdateHandler);
}

// response error handling middleware
app.useExt(handleError);
```
