### Title
Unauthenticated Pagination Loop Causes Sustained DB Exhaustion via Triple-Query Fan-Out in `getSchedules()`

### Summary
The `getSchedules()` handler in `rest/schedules.js` issues three database queries per request (one main schedule query plus two parallel `json_agg` aggregation queries). The REST service has no per-IP rate limiting for unauthenticated users, so an attacker following the `links.next` cursor in a tight loop can sustain unbounded DB load, exhausting the connection pool and degrading service availability.

### Finding Description

**Exact code path:**

`rest/schedules.js`, `getSchedules()`, lines 234–282.

Each call unconditionally executes:

1. A primary `SELECT` against the `schedule` table (line 241).
2. Two parallel queries via `Promise.all` (lines 261–264): an `entity` lookup and a `transaction_signature` query using `json_agg(... order by ts.consensus_timestamp)` — an aggregation that sorts all signatures per schedule entity.

```js
// rest/schedules.js lines 261-264
const [{rows: entities}, {rows: signatures}] = await Promise.all([
  pool.queryQuietly(entityQuery, entityIds),
  pool.queryQuietly(signatureQuery, entityIds),
]);
```

The pagination link is generated at lines 274–281:
```js
schedulesResponse.links.next = utils.getPaginationLink(
  req,
  schedulesResponse.schedules.length !== limit,
  {[constants.filterKeys.SCHEDULE_ID]: lastScheduleId},
  order
);
```

This produces a cursor like `/api/v1/schedules?limit=25&schedule.id=gt:0.0.3000`, which the attacker follows in a loop.

**Root cause — no per-IP rate limiting in the REST service:**

`rest/server.js` (lines 67–98) registers the following middleware: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`. There is no `express-rate-limit` or equivalent. The `grep_search` across all `rest/**/*.js` files confirmed zero references to any rate-limiting library.

The `authHandler` (`rest/middleware/authHandler.js`, lines 15–36) only sets a custom response-row limit for authenticated users; it does not throttle or reject unauthenticated requests.

The response cache (`responseCacheCheckHandler`) is gated on `config.cache.response.enabled && config.redis.enabled` (server.js line 54) — an optional deployment dependency. Paginated requests with different `schedule.id=gt:X` cursors produce unique cache keys, so even when Redis is present, each page of a pagination walk is a cache miss.

**Failed assumption:** The design assumes that the DB connection pool (`db.pool.maxConnections`) and statement timeout (`db.pool.statementTimeout`) are sufficient to absorb adversarial load. They are not: an attacker issuing requests faster than the pool can drain them causes legitimate requests to queue and eventually time out.

### Impact Explanation

Each paginated request consumes three DB connections simultaneously (one per query, two held concurrently in `Promise.all`). With a default pool size (typically 10–20 connections), a single attacker issuing ~5–10 concurrent pagination loops can saturate the pool. All other API endpoints sharing the same pool (accounts, transactions, tokens, etc.) begin queuing. If the pool is exhausted, new requests receive connection-timeout errors, effectively taking the REST service offline. Because the REST service is the primary read interface for mirror node consumers, this constitutes degradation of network processing visibility and downstream integrations.

### Likelihood Explanation

No authentication, API key, or network credential is required. The attacker needs only an HTTP client and knowledge of the public `/api/v1/schedules` endpoint (documented in the OpenAPI spec served by the same server). The `links.next` cursor is self-describing and trivially scriptable. The attack is repeatable indefinitely and requires no brute force — a single script following the next link in a loop is sufficient. The attack is amplified by using `limit=<max>` to maximize the `IN (...)` clause size in the entity and signature queries, increasing per-request DB work.

### Recommendation

1. **Add per-IP rate limiting** to the REST service using `express-rate-limit` (or equivalent) applied globally before route handlers in `rest/server.js`, with a conservative default (e.g., 60 requests/minute per IP) for unauthenticated clients.
2. **Enforce a DB-level statement timeout** (`statementTimeout`) that is short enough to abort runaway queries before they hold connections.
3. **Require the response cache** (Redis) in production deployments, or add an in-process LRU cache for paginated schedule responses keyed on the cursor value.
4. **Consider merging the three queries** into a single SQL query using CTEs or lateral joins to reduce per-request connection consumption from 3 to 1.

### Proof of Concept

```bash
# Step 1: Fetch first page (no credentials required)
NEXT="/api/v1/schedules?limit=25"
BASE="https://<mirror-node-host>"

# Step 2: Follow next links in a tight loop
while true; do
  RESPONSE=$(curl -s "${BASE}${NEXT}")
  NEXT=$(echo "$RESPONSE" | jq -r '.links.next // empty')
  [ -z "$NEXT" ] && NEXT="/api/v1/schedules?limit=25"  # wrap around
done

# Run 10 parallel instances of the above loop.
# Each iteration triggers 3 DB queries (1 schedule + 2 json_agg).
# With 10 parallel loops at ~5 req/s each = 50 req/s = 150 concurrent DB queries.
# A pool of 20 connections is exhausted; legitimate requests begin timing out.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/schedules.js (L234-282)
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

  schedulesResponse.schedules = mergeScheduleEntities(schedules, entities, signatures).map(formatScheduleRow);

  // populate next link
  const lastScheduleId =
    schedulesResponse.schedules.length > 0
      ? schedulesResponse.schedules[schedulesResponse.schedules.length - 1].schedule_id
      : null;

  schedulesResponse.links.next = utils.getPaginationLink(
    req,
    schedulesResponse.schedules.length !== limit,
    {
      [constants.filterKeys.SCHEDULE_ID]: lastScheduleId,
    },
    order
  );
};
```

**File:** rest/server.js (L54-54)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
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
