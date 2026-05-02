### Title
Connection Pool Exhaustion via Unauthenticated Concurrent Requests to `/api/v1/schedules` During Network Partition

### Summary
The `getSchedules()` handler in `rest/schedules.js` issues up to three sequential/parallel `pool.queryQuietly()` calls per request with no application-level rate limiting. The REST API pool defaults to 10 connections (`maxConnections: 10`). During a network partition between the REST API and PostgreSQL, each in-flight connection hangs indefinitely at the TCP layer because the server-side `statement_timeout` cannot deliver its error response to the client, allowing an unprivileged attacker sending as few as 10 concurrent requests to exhaust the entire pool and deny service to all other users.

### Finding Description
**Exact code path:**

`rest/schedules.js`, `getSchedules()`, lines 234–282:

- **Line 241**: First `pool.queryQuietly(schedulesQuery, params)` — sequential, holds 1 connection until the query completes or the TCP socket is torn down.
- **Lines 261–264**: `Promise.all([pool.queryQuietly(entityQuery, entityIds), pool.queryQuietly(signatureQuery, entityIds)])` — fires only if the first query returns rows, holding 2 additional connections simultaneously.

**Root cause — failed assumption:** The code assumes `statement_timeout` (default 20 000 ms, set at the PostgreSQL session level via `rest/dbpool.js` line 15) will bound connection hold time. This assumption fails during a network partition. `statement_timeout` is a server-side PostgreSQL mechanism; when the TCP path is severed, PostgreSQL may fire the timeout and attempt to send an error, but the response never reaches the Node.js client. The client-side socket remains open until the OS TCP keepalive fires (Linux default: ~7 200 s / 2 hours). `connectionTimeoutMillis` (default 20 000 ms, `dbpool.js` line 13) governs only how long a caller waits to *acquire* a free slot from the pool — it does not bound how long an already-checked-out connection is held.

**No rate limiting:** `rest/server.js` registers no rate-limiting middleware for the `/schedules` route. The middleware stack is: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler` — none of which throttle request concurrency or per-IP connection usage. The throttling found in the codebase (`web3/ThrottleManagerImpl`, Traefik `rateLimit` in the Rosetta chart) does not apply to the Node.js REST API.

**Pool size:** Default `maxConnections` is 10 (`docs/configuration.md` line 556, `dbpool.js` line 14).

**`queryQuietly` implementation** (`rest/utils.js` lines 1518–1520): without a `preQueryHint`, it calls `this.query(query, params)` — node-postgres internally checks out a connection, sends the query, and holds the connection until a response arrives. During a partition the response never arrives.

### Impact Explanation
With 10 max pool connections and each request holding at least 1 connection (and up to 3 if the first query returns rows before the partition worsens), an attacker needs only 10 concurrent requests to saturate the pool. Once saturated, every subsequent request from any user waits up to `connectionTimeoutMillis` (20 s) and then fails with a `DbError`. The entire `/api/v1/schedules` endpoint (and any other endpoint sharing the same pool) becomes unavailable for the duration of the partition plus the TCP keepalive drain period — potentially hours. This is a full REST API denial-of-service affecting all users, not just the attacker.

### Likelihood Explanation
The attacker requires no credentials, no special knowledge beyond the public API, and no ability to cause the partition — only the ability to detect or be informed of one (e.g., via monitoring, error-rate spikes, or coordinated timing). Network partitions between application and database tiers occur in cloud environments due to node restarts, rolling upgrades, AZ failovers, and misconfigured security groups. The attack payload is trivially scriptable: 10 concurrent HTTP GET requests. The absence of any rate limiting or per-IP concurrency cap means the attack is repeatable at zero cost.

### Recommendation
1. **Add a client-side query timeout** in `queryQuietly` using `pg`'s `query_timeout` option or by wrapping `this.query()` in a `Promise.race` with a `setTimeout` reject, so connections are released even when the server is unreachable.
2. **Add application-level rate limiting** (e.g., `express-rate-limit`) to the REST API, scoped per IP, before the route handlers in `server.js`.
3. **Limit per-request pool concurrency** — consider a semaphore or circuit-breaker pattern so a single request cannot hold more than one connection at a time, or so the pool degrades gracefully under saturation.
4. **Increase `maxConnections`** or deploy a connection pooler (PgBouncer is already referenced in the Helm chart) in front of PostgreSQL to absorb burst demand.
5. **Set TCP keepalive** on the pool connections (`keepAlive: true`, `keepAliveInitialDelayMillis`) so the OS detects dead connections faster than the default 2-hour keepalive interval.

### Proof of Concept
**Preconditions:** Network partition between the REST API pod and PostgreSQL is active (or intermittent). Attacker has HTTP access to the public REST API endpoint.

**Steps:**
```bash
# 1. Confirm the endpoint is reachable before the partition
curl "https://<host>/api/v1/schedules?account.id=gte:0.0.1&schedule.id=lt:999999&order=desc&limit=100"

# 2. During the partition, send 10+ concurrent requests (exhausts default pool of 10)
for i in $(seq 1 15); do
  curl -s "https://<host>/api/v1/schedules?account.id=gte:0.0.1&schedule.id=lt:999999&order=desc&limit=100" &
done
wait

# 3. Immediately send a legitimate request — it will block for connectionTimeoutMillis (20s) then fail
curl -v "https://<host>/api/v1/schedules"
# Expected: hangs ~20s, then returns 500 / DbError (pool connection timeout)

# 4. All other REST API endpoints sharing the pool are also affected
curl -v "https://<host>/api/v1/transactions"
# Expected: same failure
```

**Result:** The pool is exhausted for the duration of the partition (potentially hours due to TCP keepalive). All REST API users receive errors. The attacker requires no authentication and spends negligible resources. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rest/utils.js (L1479-1546)
```javascript
const getPoolClass = () => {
  const {Pool} = pg;
  Pool.prototype.queryQuietly = async function (query, params = [], preQueryHint = undefined) {
    let client;
    let result;
    let startTime;

    params = Array.isArray(params) ? params : [params];
    const clientErrorCallback = (error) => {
      logger.error(`error event emitted on pg pool. ${error.stack}`);
    };

    const traceEnabled = logger.isTraceEnabled();
    if (traceEnabled || isTestEnv()) {
      const callerInfo = new Error().stack
        .split('\n')
        .splice(1)
        .filter((s) => !(s.includes('utils.js') || s.includes('baseService.js')))
        .map((entry) => {
          const result = entry.match(/^\s*at\s+(\S+)[^(]+\((.*\/(.*\.js)):(\d+):.*\)$/);
          return result?.length === 5 && {function: result[1], file: result[3], line: result[4], path: result[2]};
        })[0];

      if (isTestEnv()) {
        await recordQuery(callerInfo, query);
      }

      if (traceEnabled) {
        startTime = Date.now();
        const {format} = await import('sql-formatter');
        const prettyQuery = format(query, {language: 'postgresql'});
        logger.trace(
          `${callerInfo.function} (${callerInfo.file}:${
            callerInfo.line
          })\nquery: ${prettyQuery}\nparams: ${JSONStringify(params)}`
        );
      }
    }

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

      if (traceEnabled) {
        const elapsed = Date.now() - startTime;
        logger.trace(`Query took ${elapsed} ms and returned ${result.rows.length} entries`);
      }

      return result;
    } catch (err) {
      if (client !== undefined) {
        await client.query('rollback');
      }
      throw new DbError(err.message);
    } finally {
      if (client !== undefined) {
        client.off('error', clientErrorCallback);
        client.release();
      }
    }
  };
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

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```
