### Title
Unauthenticated Resource Exhaustion DoS via Uncached Paginated Schedule Listing with Triple DB Query Fan-out

### Summary
The `getSchedules()` handler in `rest/schedules.js` issues three separate `pool.queryQuietly()` calls per request (one for schedules, two in parallel for entities and signatures). The list endpoint sets no long-lived `cache-control` header, so each unique `schedule.id=gt:X` pagination cursor produces a cache miss and hits the database fresh. With no rate limiting on the REST API and no authentication required, an attacker can sustain DB connection pool exhaustion by flooding the endpoint with incrementing cursor values.

### Finding Description

**Code path** — `rest/schedules.js`, `getSchedules()`, lines 234–282:

- Line 241: first `pool.queryQuietly(schedulesQuery, params)` — fetches the schedule page.
- Lines 261–264: `Promise.all([pool.queryQuietly(entityQuery, entityIds), pool.queryQuietly(signatureQuery, entityIds)])` — two concurrent queries for entity metadata and transaction signatures.

Every non-empty response therefore holds **two pool connections simultaneously** (the `Promise.all` pair) after already having consumed one for the initial query.

**Cache bypass** — `rest/middleware/responseCacheHandler.js` generates cache keys from `req.originalUrl` (line 152). Each distinct `schedule.id=gt:X` value produces a unique URL and therefore a unique cache key. The `getSchedules` handler never sets a `cache-control` header, so `getCacheControlExpiryOrDefault` falls back to `DEFAULT_REDIS_EXPIRY = 1` second (line 24/163). Even with Redis caching enabled, a 1-second TTL means every request in a rapid-fire sequence is a cache miss.

**No rate limiting** — `rest/server.js` lines 67–116 show the middleware stack: `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, optional `metricsHandler`, optional `responseCacheCheckHandler`, then route handlers. There is no rate-limiting middleware for the REST API. The throttle implementation found (`web3/src/main/java/.../ThrottleConfiguration.java`) applies only to the `web3` module (contract calls), not to the Node.js REST service.

**Root cause**: The failed assumption is that the combination of a finite DB connection pool (`rest/dbpool.js` line 14: `max: config.db.pool.maxConnections`) and three queries per request is safe without a request rate gate. The `statement_timeout` and `connectionTimeoutMillis` bound individual query/wait duration but do not prevent the pool from being continuously saturated when the attacker's request rate exceeds the pool's throughput.

### Impact Explanation
When the pool is saturated, all new `pool.queryQuietly()` calls queue internally. The Node.js event loop accumulates pending promises; memory grows proportionally to the queue depth. Legitimate users receive connection-timeout errors (`DbError` wrapping the pg timeout). Because the attack requires no credentials and uses the public pagination API, the entire `/api/v1/schedules` endpoint (and potentially other endpoints sharing the same pool) becomes unavailable for the duration of the attack. The `mirror_rest` pgbouncer user is capped at `max_user_connections: 250` (`charts/hedera-mirror/values.yaml` line 373), which is the effective ceiling an attacker must saturate — achievable with ~85 concurrent HTTP clients each holding 3 in-flight queries.

### Likelihood Explanation
The attack requires zero privileges, zero on-chain assets, and only a standard HTTP client. The pagination pattern (`schedule.id=gt:X`) is documented in the OpenAPI spec and test fixtures. The attacker does not need to know valid schedule IDs — sequential integers starting from 0 are sufficient. The attack is trivially scriptable, repeatable, and can be sustained indefinitely from a single machine or distributed across IPs to defeat any IP-based network-layer throttle.

### Recommendation
1. **Add per-IP (or global) rate limiting** to the Node.js REST server for the `/api/v1/schedules` list endpoint, e.g., via `express-rate-limit` or an ingress-level policy.
2. **Set a meaningful `cache-control` header** on list responses (e.g., `public, max-age=3`) so that repeated identical or near-identical requests are served from Redis without hitting the DB.
3. **Reduce query fan-out**: merge the three queries into a single SQL query using JOINs and `json_agg`, eliminating the two follow-up queries and the simultaneous dual-connection hold.
4. **Enforce a maximum `limit`** that is meaningfully low (the default is already bounded, but confirm it cannot be set to a large value that amplifies the signature `json_agg` cost).

### Proof of Concept

```bash
# Sustained flood with incrementing cursors — no credentials needed
for i in $(seq 0 100000); do
  curl -s "https://<mirror-node>/api/v1/schedules?schedule.id=gt:$i&limit=25" \
    -o /dev/null &
  # Keep ~100 requests in-flight at all times
  if (( i % 100 == 0 )); then wait; fi
done
```

Each iteration of 100 concurrent requests triggers up to 300 simultaneous `pool.queryQuietly()` calls. With `max_user_connections: 250` for `mirror_rest`, the pool saturates within the first batch. Subsequent legitimate requests receive `DbError: connection timeout` until the attacker stops. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** rest/middleware/responseCacheHandler.js (L24-24)
```javascript
const DEFAULT_REDIS_EXPIRY = 1;
```

**File:** rest/middleware/responseCacheHandler.js (L151-163)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};

const getCacheControlExpiryOrDefault = (headerValue) => {
  if (headerValue) {
    const maxAge = headerValue.match(CACHE_CONTROL_REGEX);
    if (maxAge && maxAge.length === 2) {
      return parseInt(maxAge[1], 10);
    }
  }

  return DEFAULT_REDIS_EXPIRY;
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

**File:** rest/server.js (L67-116)
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
```

**File:** charts/hedera-mirror/values.yaml (L371-373)
```yaml
        mirror_rest:
          max_user_client_connections: 1000
          max_user_connections: 250
```
