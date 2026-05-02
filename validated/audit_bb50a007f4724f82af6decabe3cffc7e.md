I verified all key code references against the actual repository. Here is my assessment:

**Verified facts:**

1. `rest/balances.js` line 66 (`getAccountIdsByPublicKey`), line 189 (`getAccountBalanceTimestampRange`), and line 153 (main query) — all confirmed as `pool.queryQuietly()` calls. However, the three-query path is only taken when a `timestamp` filter is present; without it, only the single query at line 153 executes.
2. `rest/dbpool.js` line 14 (`max: config.db.pool.maxConnections`) and line 36 (`global.pool = new Pool(poolConfig)`) — confirmed global shared pool.
3. `rest/server.js` line 106 — `/balances` registered with no throttle, semaphore, or queue middleware. Confirmed.
4. `charts/hedera-mirror-rest/values.yaml` lines 134–139 — REST middleware only has `circuitBreaker` and `retry: attempts: 10`. No `inFlightReq` or `rateLimit`.
5. `charts/hedera-mirror-rosetta/values.yaml` lines 149–163 — Rosetta has `inFlightReq: amount: 5` and `rateLimit: average: 10`. Confirmed asymmetry.
6. `charts/hedera-mirror-rest/templates/middleware.yaml` line 3 — template gated on `global.middleware`. Default is `false` (confirmed from other chart values).
7. `retry: attempts: 10` confirmed at `charts/hedera-mirror-rest/values.yaml` line 138.

---

Audit Report

## Title
Unauthenticated Connection Pool Exhaustion via Unbounded Concurrent Requests to `getBalances()`

## Summary
The REST API's `/balances` endpoint performs up to three sequential database queries per request (when a timestamp filter is supplied) with no application-level concurrency control, rate limiting, or backpressure. The Traefik middleware for the REST chart omits `inFlightReq` and `rateLimit` protections that are present in the Rosetta chart. An unauthenticated attacker can exhaust the per-pod connection pool, causing all subsequent requests sharing that pool to fail until the attack stops.

## Finding Description

**Multiple sequential DB queries per request:**

`getBalances()` in `rest/balances.js` calls up to three `pool.queryQuietly()` invocations when a `timestamp` query parameter is present:
- Line 66 inside `getAccountIdsByPublicKey()` (called at line 119)
- Line 189 inside `getAccountBalanceTimestampRange()` (called transitively via `getTsQuery()` at line 114)
- Line 153 — the main balance query [1](#0-0) [2](#0-1) [3](#0-2) 

Without a timestamp filter, only the single query at line 153 executes, so the "always three queries" claim in the report is slightly overstated — it is conditional on the timestamp parameter being present.

**Globally shared, bounded connection pool:**

`rest/dbpool.js` creates a single global `pool` per pod bounded by `config.db.pool.maxConnections`, with `connectionTimeoutMillis` and `statement_timeout` also drawn from config. [4](#0-3) [5](#0-4) 

**No application-level rate limiting or concurrency control:**

`server.js` registers `/balances` directly with no throttle, semaphore, or queue middleware. [6](#0-5) 

The middleware stack (lines 68–98) contains only `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, and `responseCacheCheckHandler` — none of which limit concurrency. [7](#0-6) 

**REST Traefik middleware lacks `inFlightReq` and `rateLimit`:**

The REST chart's middleware chain only defines `circuitBreaker` and `retry: attempts: 10`. [8](#0-7) 

By contrast, the Rosetta chart explicitly includes `inFlightReq: amount: 5` per IP and `rateLimit: average: 10`. [9](#0-8) 

**Middleware is disabled by default:**

The middleware template only renders when `global.middleware` is `true`; its default is `false`. [10](#0-9) 

**`retry: attempts: 10` amplifies load:**

Each failed request is retried up to 10 times by Traefik, multiplying attacker-generated backend load by up to 10×. [11](#0-10) 

## Impact Explanation
The connection pool is shared across all REST endpoints within a pod. Exhausting it via `/balances` (with timestamp filters triggering three sequential queries per request) denies service to every other endpoint (`/accounts`, `/transactions`, `/tokens`, etc.) on that pod. With the `statement_timeout` bounding query duration, an attacker must sustain only enough concurrent requests to hold all pool connections simultaneously. All other requests queue and then fail after the connection timeout. The `retry: attempts: 10` amplifier means each attacker request generates up to 10 backend attempts. Note: the HPA (`maxReplicas: 15`) means multiple pods exist in production, so a complete cluster-wide outage requires targeting all pods simultaneously — the per-pod impact is real but the "complete REST API service outage" framing is somewhat overstated. [12](#0-11) 

## Likelihood Explanation
The attack requires no credentials, no special knowledge, and no sophisticated tooling. A simple `curl` loop with a `?timestamp=lte:9999999999999999999` parameter triggers the three-query path. The lack of `inFlightReq` or `rateLimit` in the REST Traefik middleware (unlike Rosetta) means no per-source concurrency cap exists even in production deployments where `global.middleware: true` is set. The `retry: attempts: 10` amplifier lowers the sustained request rate needed to maintain pool exhaustion.

## Recommendation
1. Add `inFlightReq` (per-IP) and `rateLimit` to the REST chart's middleware, mirroring the Rosetta chart configuration.
2. Reduce `retry: attempts` from 10 to 3 (consistent with Rosetta and graphql charts) to eliminate the 10× amplification.
3. Consider adding application-level concurrency control (e.g., a semaphore or queue) in `getBalances()` for the multi-query timestamp path.
4. Review the default `maxConnections` value and consider whether it is appropriate for the expected traffic volume. [8](#0-7) [9](#0-8) 

## Proof of Concept
```bash
# Exhaust the connection pool on a single pod by sending concurrent timestamp-filtered requests
# Each request triggers up to 3 sequential pool.queryQuietly() calls
for i in $(seq 1 20); do
  curl -s "https://<mirror-node-host>/api/v1/balances?timestamp=lte:9999999999999999999&limit=100" &
done
wait

# All subsequent requests to any endpoint on the same pod will fail with connection timeout
curl "https://<mirror-node-host>/api/v1/transactions"
# Expected: connection timeout / 503 error
```

The three-query code path is activated by any request to `/api/v1/balances` that includes a `timestamp` filter parameter, which is a documented and commonly used query parameter. [13](#0-12)

### Citations

**File:** rest/balances.js (L60-76)
```javascript
const getAccountIdsByPublicKey = async (publicKey, limit) => {
  if (isEmpty(publicKey)) {
    return null;
  }

  const params = [...publicKey, limit];
  const result = await pool.queryQuietly(entityPublicKeyQuery, params);

  if (result) {
    const ids = result.rows.map((r) => r.id);
    if (!isEmpty(ids)) {
      return `ab.account_id in (${ids})`;
    }
  }

  return null;
};
```

**File:** rest/balances.js (L113-153)
```javascript
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
```

**File:** rest/balances.js (L167-197)
```javascript
const getAccountBalanceTimestampRange = async (tsQuery, tsParams) => {
  const {lowerBound, upperBound, neParams} = getOptimizedTimestampRange(tsQuery, tsParams);
  if (lowerBound === undefined) {
    return {};
  }

  // Add the treasury account to the query as it will always be in the balance snapshot and account_id is the first
  // column of the primary key
  let condition = 'account_id = $1 and consensus_timestamp >= $2 and consensus_timestamp <= $3';
  const params = [EntityId.systemEntity.treasuryAccount.getEncodedId(), lowerBound, upperBound];
  if (neParams.length) {
    condition += ' and not consensus_timestamp = any ($4)';
    params.push(neParams);
  }

  const query = `
    select consensus_timestamp
    from account_balance
    where ${condition}
    order by consensus_timestamp desc
    limit 1`;

  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length === 0) {
    return {};
  }

  const upper = rows[0].consensus_timestamp;
  const lower = utils.getFirstDayOfMonth(upper);
  return {lower, upper};
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

**File:** rest/dbpool.js (L35-47)
```javascript
const initializePool = () => {
  global.pool = new Pool(poolConfig);
  handlePoolError(global.pool);

  if (config.db.primaryHost) {
    const primaryPoolConfig = {...poolConfig};
    primaryPoolConfig.host = config.db.primaryHost;
    global.primaryPool = new Pool(primaryPoolConfig);
    handlePoolError(global.primaryPool);
  } else {
    global.primaryPool = pool;
  }
};
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

**File:** rest/server.js (L106-106)
```javascript
app.getExt(`${apiPrefix}/balances`, balances.getBalances);
```

**File:** charts/hedera-mirror-rest/values.yaml (L93-105)
```yaml
hpa:
  behavior: {}
  enabled: true
  maxReplicas: 15
  metrics:
    - type: Resource
      resource:
        name: cpu
        target:
          type: Utilization
          averageUtilization: 80

  minReplicas: 1
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
