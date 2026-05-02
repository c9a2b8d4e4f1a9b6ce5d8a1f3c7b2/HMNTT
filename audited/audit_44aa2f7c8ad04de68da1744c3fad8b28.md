### Title
Unauthenticated DB Connection Pool Exhaustion via Parallel `getSchedules()` Requests

### Summary
The `getSchedules()` handler in `rest/schedules.js` issues up to three concurrent `pool.queryQuietly()` calls per HTTP request (one sequential `schedulesQuery`, then two parallel via `Promise.all` for `entityQuery` and `signatureQuery`). The REST service has no rate limiting, concurrency cap, or per-IP throttle on this endpoint. An unprivileged attacker sending many parallel requests can exhaust the finite DB connection pool, causing `connectionTimeoutMillis` errors for all subsequent legitimate queries and degrading the mirror node REST API.

### Finding Description
**Exact code path:**

In `rest/schedules.js` lines 234–264, `getSchedules()` executes:

```js
// Line 241 — first connection acquired
const {rows: schedules} = await pool.queryQuietly(schedulesQuery, params);

// Lines 261–264 — two more connections acquired simultaneously
const [{rows: entities}, {rows: signatures}] = await Promise.all([
  pool.queryQuietly(entityQuery, entityIds),
  pool.queryQuietly(signatureQuery, entityIds),
]);
```

Each request holds up to **3 pool connections** concurrently (2 at the `Promise.all` step). The pool is configured with a hard `max: config.db.pool.maxConnections` in `rest/dbpool.js` line 14. The `queryQuietly` implementation in `rest/utils.js` lines 1518–1520 uses `this.query()` (pool-managed), which queues when the pool is saturated and throws a `DbError` after `connectionTimeoutMillis`.

**Root cause:** No application-level rate limiting, concurrency semaphore, or per-IP throttle exists in the REST service. A search across all `rest/**/*.js` files confirms zero usage of `rateLimit`, `rateLimiter`, `throttle`, `concurrency`, or `semaphore`. The `server.js` middleware stack (lines 68–144) applies only `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, and `responseHandler` — none of which limit request concurrency.

**Why existing checks fail:**
- `statement_timeout` (configured in `rest/dbpool.js` line 15) limits individual query duration but does not prevent pool exhaustion when many requests are in-flight simultaneously.
- `connectionTimeoutMillis` causes queued requests to fail with errors rather than block indefinitely, but this is the failure mode, not a mitigation.
- The throttling code found (`web3/src/main/java/.../ThrottleConfiguration.java`, `ThrottleManagerImpl.java`) belongs to the separate `web3` Java service, not the Node.js REST mirror node service.
- The Traefik `inFlightReq`/`rateLimit` middleware in `charts/hedera-mirror-rosetta/values.yaml` applies only to the Rosetta service, not the REST API.

### Impact Explanation
With a pool of `maxConnections` (e.g., default 10), an attacker sending `ceil(maxConnections/2)` concurrent requests saturates the pool. All subsequent legitimate queries — across every REST endpoint — receive connection timeout errors, returning HTTP 500 to all users. This constitutes full denial-of-service of the mirror node REST API. The mirror node is infrastructure used by wallets, explorers, and dApps; its unavailability degrades the observable state of the Hedera network for all consumers.

### Likelihood Explanation
The attack requires zero authentication, zero special knowledge, and only a standard HTTP client capable of parallel requests (e.g., `curl`, `ab`, `wrk`, Python `asyncio`). It is trivially repeatable: the attacker simply keeps a steady stream of concurrent requests open. Because each request holds connections for the duration of real DB query execution (potentially hundreds of milliseconds for `transaction_signature` aggregation), a small number of parallel connections is sufficient to maintain saturation.

### Recommendation
1. **Add a global concurrency limiter** in the Express middleware stack (e.g., `express-rate-limit` or a custom semaphore) before route handlers, capping in-flight requests per IP and globally.
2. **Reduce connections per request**: Rewrite `getSchedules()` to use a single SQL query with JOINs (as `getScheduleByIdQuery` already does at line 46–64), eliminating the `Promise.all` fan-out.
3. **Set a lower `connectionTimeoutMillis`** and expose pool saturation as a 503 (Service Unavailable) rather than 500, enabling upstream load balancers to shed load.
4. **Deploy infrastructure-level rate limiting** (e.g., Traefik `inFlightReq` + `rateLimit` middleware, as already done for the Rosetta service) in front of the REST API.

### Proof of Concept
```bash
# Exhaust a pool with maxConnections=10 using 6 concurrent requests
# (each holds 2 connections at Promise.all step = 12 > 10)
for i in $(seq 1 6); do
  curl -s "http://<mirror-node-host>/api/v1/schedules" &
done
wait

# Subsequent legitimate request receives connection timeout / HTTP 500
curl -v "http://<mirror-node-host>/api/v1/schedules"
# Expected: 500 Internal Server Error (DbError: connection timeout)
```

Repeat the loop continuously to maintain saturation. No credentials, API keys, or special headers required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/schedules.js (L234-264)
```javascript
const getSchedules = async (req, res) => {
  // extract filters from query param
  const filters = utils.buildAndValidateFilters(req.query, acceptedSchedulesParameters);

  // get sql filter query, params, order and limit from query filters
  const {filterQuery, params, order, limit} = extractSqlFromScheduleFilters(filters);
  const schedulesQuery = getSchedulesQuery(filterQuery, order, params.length);
  const {rows: schedules} = await pool.queryQuietly(schedulesQuery, params);

  const schedulesResponse = {schedules: [], links: {next: null}};
  res.locals[constants.responseDataLabel] = schedulesResponse;

  if (schedules.length === 0) {
    return;
  }

  const entityIds = schedules.map((s) => s.schedule_id);
  const positions = range(1, entityIds.length + 1)
    .map((i) => `$${i}`)
    .join(',');
  const entityQuery = `select ${entityFields} from entity where id in (${positions}) order by id ${order}`;
  const signatureQuery = `select entity_id, ${transactionSignatureJsonAgg} as signatures
    from transaction_signature ts
    where entity_id in (${positions})
    group by entity_id
    order by entity_id ${order}`;

  const [{rows: entities}, {rows: signatures}] = await Promise.all([
    pool.queryQuietly(entityQuery, entityIds),
    pool.queryQuietly(signatureQuery, entityIds),
  ]);
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

**File:** rest/utils.js (L1518-1527)
```javascript
    try {
      if (!preQueryHint) {
        result = await this.query(query, params);
      } else {
        client = await this.connect();
        client.on('error', clientErrorCallback);
        await client.query(`begin; ${preQueryHint}`);
        result = await client.query(query, params);
        await client.query('commit');
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
