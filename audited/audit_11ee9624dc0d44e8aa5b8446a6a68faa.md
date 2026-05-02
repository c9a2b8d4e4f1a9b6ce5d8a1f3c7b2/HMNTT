### Title
Unauthenticated DB Connection Pool Exhaustion via Three-Query Amplification in `getSchedules()`

### Summary
The `getSchedules()` handler in `rest/schedules.js` unconditionally fires three database queries per request (one sequential, then two parallel via `Promise.all`) against a default pool of only 10 connections, with no application-level rate limiting. An unauthenticated attacker sending a sustained flood of concurrent requests can exhaust the connection pool, causing the mirror node REST API to become entirely unavailable and unable to serve any queries.

### Finding Description
**Exact code path:** `rest/schedules.js`, `getSchedules()`, lines 234–282.

**Query 1 (line 241):** `schedulesQuery` — acquires one pool connection, runs, releases.
```
const {rows: schedules} = await pool.queryQuietly(schedulesQuery, params);
```
**Queries 2 & 3 (lines 261–264):** `entityQuery` and `signatureQuery` — acquired simultaneously via `Promise.all`, each holding a separate pool connection:
```js
const [{rows: entities}, {rows: signatures}] = await Promise.all([
  pool.queryQuietly(entityQuery, entityIds),
  pool.queryQuietly(signatureQuery, entityIds),
]);
```
The `signatureQuery` uses `json_agg(...) group by entity_id` on the `transaction_signature` table — a potentially expensive aggregation, especially with many signatures per schedule.

**Pool configuration** (`rest/dbpool.js` line 14; `docs/configuration.md` line 556): default `maxConnections = 10`, `statementTimeout = 20000ms`. With 5 concurrent requests all reaching the `Promise.all` stage simultaneously: 5 × 2 = 10 connections → pool fully exhausted. Subsequent requests queue or fail with connection timeout.

**No rate limiting:** `rest/server.js` (lines 67–98) registers only cors, compression, httpContext, requestLogger, authHandler, metricsHandler, and responseCacheCheckHandler — no per-IP or global request rate limiter. The middleware directory (`rest/middleware/`) contains no throttling component.

**No authentication required:** `/api/v1/schedules` is a public GET endpoint (server.js line 115).

**Limit cap is insufficient:** `getLimitParamValue()` in `rest/utils.js` (lines 544–553) caps the `limit` parameter at `responseLimit.max` (default 100), but this only bounds result size — it does not prevent connection exhaustion from concurrent requests.

### Impact Explanation
With the pool exhausted, all subsequent `pool.queryQuietly()` calls across every REST endpoint block waiting for a free connection. The mirror node REST API becomes entirely unresponsive — users and operators cannot query transaction status, account balances, schedules, or any other data. The `statementTimeout` of 20 seconds means connections are held for up to 20 seconds per request, making sustained exhaustion trivial to maintain. Note: the mirror node is a read-only service and does not directly participate in Hedera consensus; the impact is full REST API unavailability, not network-wide transaction confirmation failure.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and no special knowledge beyond the public API spec. Five to ten concurrent HTTP connections from a single host are sufficient to exhaust the default pool. The attack is trivially repeatable and scriptable (e.g., `ab`, `wrk`, or a simple async loop). No CAPTCHA, API key, or connection-level throttle exists at the application layer to prevent it.

### Recommendation
1. **Add application-level rate limiting** (e.g., `express-rate-limit`) per IP before route handlers in `rest/server.js`.
2. **Increase the default pool size** (`hiero.mirror.rest.db.pool.maxConnections`) to match expected concurrency, or deploy PgBouncer in front of the REST service (the Helm chart already configures PgBouncer for `mirror_rest` with `max_user_connections: 250`; ensure it is used in all deployments).
3. **Reduce `statementTimeout`** for the schedules queries to limit how long connections are held.
4. **Consider merging the three queries** into a single SQL query using JOINs (as already done in `getScheduleByIdQuery` at lines 46–64), eliminating the multi-connection pattern entirely.

### Proof of Concept
```bash
# Exhaust the default pool of 10 connections with 6 concurrent persistent floods
# Each request triggers 2 simultaneous DB connections at the Promise.all stage
for i in $(seq 1 6); do
  while true; do
    curl -s "http://<mirror-node-host>:5551/api/v1/schedules?limit=100" > /dev/null
  done &
done

# Verify: subsequent requests to any endpoint hang or return 503/timeout
curl -v "http://<mirror-node-host>:5551/api/v1/transactions"
```
Expected result: the transactions request (and all others) hangs until `connectionTimeoutMillis` (default 20 seconds) elapses, then fails — confirming pool exhaustion. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest/schedules.js (L46-64)
```javascript
const getScheduleByIdQuery = `
  select
    s.consensus_timestamp,
    s.creator_account_id,
    e.deleted,
    s.executed_timestamp,
    s.expiration_time,
    e.key,
    e.memo,
    s.payer_account_id,
    s.schedule_id,
    s.transaction_body,
    s.wait_for_expiry,
    ${transactionSignatureJsonAgg} as signatures
  from schedule s
  left join entity e on e.id = s.schedule_id
  left join transaction_signature ts on ts.entity_id = s.schedule_id
  where s.schedule_id = $1
  group by s.schedule_id, e.id`;
```

**File:** rest/schedules.js (L241-264)
```javascript
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
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

**File:** rest/utils.js (L533-553)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};

/**
 * Gets the limit param value, if not exists, return the default; otherwise cap it at max.
 * Note if values is an array, the last one is honored.
 * @param {string[]|string} values Values of the limit param
 * @return {number}
 */
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```
