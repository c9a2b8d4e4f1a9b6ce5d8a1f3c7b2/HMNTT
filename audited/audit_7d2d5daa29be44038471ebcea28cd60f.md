### Title
Unauthenticated Connection Pool Exhaustion via Unbounded Concurrent Requests to `getBalances()`

### Summary
`getBalances()` in `rest/balances.js` performs up to three sequential database queries per request with no concurrency control, rate limiting, or backpressure. The default connection pool is capped at 10 connections with a 20-second statement timeout. An unauthenticated attacker sending a small burst of concurrent requests can hold all pool connections simultaneously, causing every subsequent REST API request (across all endpoints sharing the pool) to fail with a connection timeout error until the attack stops.

### Finding Description

**Code path — `getBalances()` acquires connections sequentially per request:**

`rest/balances.js` lines 83–156 show three distinct `pool.queryQuietly()` calls per request:
- Line 66 (`getAccountIdsByPublicKey`) — first connection acquisition
- Line 189 (`getAccountBalanceTimestampRange`) — second connection acquisition  
- Line 153 (main balance query) — third connection acquisition [1](#0-0) 

**Pool is globally shared and tiny by default:**

`rest/dbpool.js` creates a single global `pool` with `max: config.db.pool.maxConnections`. [2](#0-1) 

The documented default is **10 connections** with a **20-second statement timeout** and a **20-second connection timeout**. [3](#0-2) 

**No application-level rate limiting or concurrency control:**

`server.js` registers the `/balances` route with no throttle, semaphore, or queue middleware. The middleware stack is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler`. None of these limit concurrency. [4](#0-3) 

**Traefik middleware for the REST chart is missing `inFlightReq` and `rateLimit`:**

The REST chart's middleware only defines `circuitBreaker` and `retry`. Compare to the Rosetta chart which explicitly includes `inFlightReq` (5 per IP) and `rateLimit` (10/s). [5](#0-4) [6](#0-5) 

**The Traefik middleware is disabled by default:**

The middleware template only renders when `global.middleware` is `true`. Its default value is `false`. [7](#0-6) [8](#0-7) 

Even in production (`values-prod.yaml` sets `global.middleware: true`), the REST middleware chain still lacks `inFlightReq` and `rateLimit`, so no per-source concurrency cap exists. [9](#0-8) 

**The `retry` middleware amplifies the attack:**

With `attempts: 10`, Traefik retries each failed request 10 times, multiplying attacker-generated load by 10×. [10](#0-9) 

### Impact Explanation
The 10-connection pool is shared across all REST API endpoints. Exhausting it via `/balances` denies service to every other endpoint (`/accounts`, `/transactions`, `/tokens`, etc.). With a 20-second statement timeout, an attacker needs to sustain only ~10 concurrent long-running balance queries (e.g., with a wide timestamp range) to hold all connections. All other requests queue and then fail after 20 seconds. This constitutes a complete REST API service outage for the duration of the attack. No authentication is required.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no sophisticated tooling — a single `ab` (Apache Bench) or `curl` loop from one machine suffices. The default pool size of 10 is extremely small relative to public internet traffic. The `retry: attempts: 10` amplifier means even a modest 1 req/s sustained rate generates 10 backend attempts per request. The attack is trivially repeatable and requires no state.

### Recommendation
1. **Add `inFlightReq` and `rateLimit` to the REST chart's Traefik middleware**, matching the Rosetta chart's pattern (e.g., `inFlightReq.amount: 50` globally, `rateLimit.average: 100` per source IP).
2. **Increase the default pool size** (`hiero.mirror.rest.db.pool.maxConnections`) to a value appropriate for expected concurrency (e.g., 50–100), or use PgBouncer's `max_user_client_connections` limit already configured for `mirror_rest` at 1000 client connections / 250 server connections.
3. **Add application-level concurrency limiting** in `server.js` using a middleware such as `express-rate-limit` or a semaphore before the `getBalances` handler.
4. **Reduce `retry.attempts`** from 10 to 2–3 to avoid amplifying DoS conditions.

### Proof of Concept
```bash
# Exhaust the 10-connection pool with 15 concurrent long-running balance queries
# No authentication required
for i in $(seq 1 15); do
  curl -s "http://<mirror-node-host>/api/v1/balances?timestamp=lte:9999999999.999999999&limit=100" &
done
wait

# All subsequent requests now fail with 503 or connection timeout:
curl -v "http://<mirror-node-host>/api/v1/balances"
# Expected: connection timeout after 20s or immediate 503 from exhausted pool
curl -v "http://<mirror-node-host>/api/v1/transactions"
# Expected: same failure — entire pool is exhausted, all endpoints affected
```

### Citations

**File:** rest/balances.js (L83-156)
```javascript
const getBalances = async (req, res) => {
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);

  // Parse the filter parameters for credit/debit, account-numbers, timestamp and pagination
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
  // transform the timestamp=xxxx or timestamp=eq:xxxx query in url to 'timestamp <= xxxx' SQL query condition
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
  const [balanceQuery, balanceParams] = utils.parseBalanceQueryParam(req.query, 'ab.balance');
  const [pubKeyQuery, pubKeyParams] = utils.parsePublicKeyQueryParam(req.query, 'public_key');
  const {
    query: limitQuery,
    params,
    order,
    limit,
  } = utils.parseLimitAndOrderParams(req, constants.orderFilterValues.DESC);

  res.locals[constants.responseDataLabel] = {
    timestamp: null,
    balances: [],
    links: {
      next: null,
    },
  };

  let sqlQuery;
  let sqlParams;

  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }

    const accountIdsQuery = await getAccountIdsByPublicKey(pubKeyParams, limit);
    if (pubKeyQuery && !accountIdsQuery) {
      return;
    }

    [sqlQuery, tsParams] = await getBalancesQuery(
      accountQuery,
      balanceQuery,
      accountIdsQuery,
      limitQuery,
      order,
      tsQueryResult
    );
    sqlParams = utils.mergeParams(tsParams, accountParams, balanceParams, params);
  } else {
    // use current balance from entity table when there's no timestamp query filter
    const conditions = [accountQuery, pubKeyQuery, balanceQuery].filter(Boolean).join(' and ');
    const whereClause = conditions && `where ${conditions}`;
    const tokenBalanceSubQuery = getTokenAccountBalanceSubQuery(order);
    sqlParams = utils.mergeParams(tsParams, accountParams, pubKeyParams, balanceParams, params);
    sqlQuery = `
      with entity_balance as (
        select id as account_id, balance, balance_timestamp as consensus_timestamp, public_key
        from entity
        where type in ('ACCOUNT', 'CONTRACT')
      )
      select ab.*, (${tokenBalanceSubQuery}) as token_balances
      from entity_balance ab
      ${whereClause}
      order by ab.account_id ${order}
      ${limitQuery}`;
  }

  const pgSqlQuery = utils.convertMySqlStyleQueryToPostgres(sqlQuery);
  const result = await pool.queryQuietly(pgSqlQuery, sqlParams);
  res.locals[constants.responseDataLabel] = formatBalancesResult(req, result, limit, order);
  logger.debug(`getBalances returning ${result.rows.length} entries`);
};
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

**File:** rest/server.js (L68-106)
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
```

**File:** charts/hedera-mirror-rest/values.yaml (L82-91)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
  podAnnotations: {}
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

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-163)
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
```

**File:** charts/hedera-mirror-rest/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** charts/hedera-mirror/values-prod.yaml (L7-8)
```yaml
global:
  middleware: true
```
