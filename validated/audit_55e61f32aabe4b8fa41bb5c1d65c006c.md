I verified all cited code references against the actual repository. Here is my assessment:

**Verified accurate:**
- `getOneAccount()` at `rest/accounts.js:396–495` matches the described flow exactly. [1](#0-0) 
- `balances.getAccountBalanceTimestampRange()` at line 435 calls `pool.queryQuietly` at `rest/balances.js:189`; when `rows.length === 0` it returns `{}` with `upper === undefined`. [2](#0-1) 
- The `else` branch at line 460–463 sets `accountBalanceQuery.forceUnionEntityHistory = true`. [3](#0-2) 
- `needHistoricalBalanceInfo` at line 164 is true when `forceUnionEntityHistory` is set, causing `entityTable` to become a full `UNION ALL` between `entity` and `entity_history`. [4](#0-3) 
- `entityPromise = pool.queryQuietly(entityQuery, entityParams)` at line 487 and `transactionsPromise` at lines 491–493 run concurrently via `Promise.all` at line 495. [5](#0-4) 
- `pool.queryQuietly` at `transactions.js:483` (timestamp query) and `transactions.js:662` (details query on cache miss) are both confirmed. [6](#0-5) [7](#0-6) 
- `dbpool.js` confirms `max: config.db.pool.maxConnections`, `connectionTimeoutMillis`, and `statement_timeout` as the only pool-level guards. [8](#0-7) 
- `server.js` contains no rate-limiting middleware — only `cors`, `compression`, `httpContext`, `authHandler`, `metricsHandler`, and response cache handlers. [9](#0-8) 
- `grep` for `rateLimit|throttle|concurrency|express-rate` in `rest/**/*.js` returned zero production-code hits.

**One minor inaccuracy in the report:** The claim of "3–4 connections simultaneously" is slightly overstated. Query 1 (`balances.js:189`) is `await`-ed and its connection is released before line 487 is reached. The true peak concurrent connections per request is **2** (entity UNION ALL + transaction timestamps, via `Promise.all`), with a potential 3rd (transaction details) running sequentially after the timestamps query resolves on a cache miss — not all held at the same time. This does not invalidate the vulnerability; it slightly reduces the amplification factor.

---

# Audit Report

## Title
Unauthenticated Timestamp Filter Triggers UNION ALL Query and Concurrent DB Connections Leading to Connection Pool Exhaustion DoS

## Summary
Any unauthenticated caller can supply `GET /api/v1/accounts/:id?timestamp=lte:1` to force the `getOneAccount()` handler into a code path that (a) builds a costly `entity UNION ALL entity_history` query and (b) runs it concurrently with a transaction-timestamp query, consuming up to 3 database connections per request (2 concurrently, 1 sequentially on cache miss). With no per-IP or global rate limiting in the REST layer, a modest number of concurrent attackers can exhaust the shared connection pool and deny service to all API endpoints.

## Finding Description

**Step 1 — Sequential balance-snapshot lookup (`rest/accounts.js:435`, `rest/balances.js:189`):**
`await balances.getAccountBalanceTimestampRange(...)` issues `pool.queryQuietly` against `account_balance`. When the supplied timestamp predates all snapshots, `rows.length === 0` and the function returns `{}` (`upper === undefined`). [2](#0-1) 

**Step 2 — `forceUnionEntityHistory` set (`rest/accounts.js:463`):**
The `else` branch sets `accountBalanceQuery.forceUnionEntityHistory = true`. [10](#0-9) 

**Step 3 — Expensive UNION ALL query constructed (`rest/accounts.js:164`, `210–219`):**
`needHistoricalBalanceInfo` evaluates to `true`, causing `entityTable` to be built as a full `UNION ALL` between `entity` and `entity_history` — significantly more expensive than a plain `entity` lookup. [11](#0-10) 

**Step 4 — Two concurrent DB operations (`rest/accounts.js:487–495`):**
`entityPromise = pool.queryQuietly(entityQuery, entityParams)` (connection A) and `transactionsPromise = transactions.doGetTransactions(...)` (which internally calls `pool.queryQuietly` at `transactions.js:483`, connection B) are both started before `await Promise.all(...)` at line 495. [5](#0-4) 

**Step 5 — Potential third connection on cache miss (`rest/transactions.js:662`):**
After `getTransactionTimestamps` resolves, `doGetTransactions` calls `cache.get(..., loader, ...)`. On a cache miss, `loader` invokes `getTransactionsDetails` → `pool.queryQuietly` (connection C). [12](#0-11) [7](#0-6) 

**Why existing guards fail:**
- `statement_timeout` limits individual query duration but does not prevent many connections from being held simultaneously across concurrent requests. [8](#0-7) 
- `connectionTimeoutMillis` causes new requests to fail fast once the pool is full, but does not prevent the pool from being filled in the first place.
- No rate-limiting, throttling, or concurrency-cap middleware exists in `rest/server.js` or any handler. [9](#0-8) 

## Impact Explanation
Once the connection pool (`max: config.db.pool.maxConnections`) is exhausted, every subsequent request to any endpoint that issues a DB query fails with a connection timeout error. This is a full denial-of-service of the mirror node REST API — not limited to `/accounts`. The UNION ALL query against both `entity` and `entity_history` is more expensive than a normal entity lookup, amplifying per-request DB load and reducing the number of concurrent attackers needed to exhaust the pool.

## Likelihood Explanation
The attack requires zero authentication, zero special knowledge, and zero prior account state. The trigger (`timestamp=lte:1`) is trivially constructed and requires no request body. The attack is repeatable, scriptable, and low-cost to the attacker. A single attacker with concurrent HTTP connections numbering roughly `maxConnections / 2` can sustain pool exhaustion indefinitely, since each request holds 2 connections concurrently during the `Promise.all` phase.

## Recommendation
1. **Rate limiting:** Add per-IP request rate limiting middleware (e.g., `express-rate-limit`) in `rest/server.js` before route handlers, with tighter limits on historically expensive endpoints like `/accounts/:id`.
2. **Concurrency cap:** Introduce a global or per-endpoint concurrency limiter (e.g., `p-limit` or a semaphore) to bound the number of in-flight DB-touching requests.
3. **Query cost guard:** Consider rejecting or short-circuiting requests where `forceUnionEntityHistory` would be triggered (e.g., return a 400 or 404 immediately when no balance snapshot exists for the given timestamp range, rather than falling back to the expensive UNION ALL path).
4. **Pool sizing and observability:** Expose pool utilization metrics and alert on near-exhaustion conditions so operators can respond before full DoS occurs.

## Proof of Concept

```bash
# Flood the endpoint with concurrent requests using a timestamp that predates all balance snapshots
# Replace <NODE_ID> with any valid account id (e.g., 0.0.2)
seq 1 200 | xargs -P 200 -I{} \
  curl -s -o /dev/null -w "%{http_code}\n" \
  "https://<mirror-node-host>/api/v1/accounts/0.0.2?timestamp=lte:1"
```

Expected result: after the pool is exhausted, responses transition from `200` to `503` or connection timeout errors for all API endpoints, not just `/accounts`.

### Citations

**File:** rest/accounts.js (L164-219)
```javascript
  const needHistoricalBalanceInfo = accountBalanceQuery.query || accountBalanceQuery.forceUnionEntityHistory;
  const queries = [];
  let selectTokenBalance;
  if (needHistoricalBalanceInfo) {
    // Return empty array if forceUnionEntityHistory is true, because there is no token balance info wrt the entity
    // balance timestamp
    selectTokenBalance = accountBalanceQuery.query
      ? `(
          select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select distinct on (token_id) token_id, balance
            from token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}, consensus_timestamp desc
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance
        ) as token_balances`
      : "'[]'::jsonb as token_balances";
  } else {
    queries.push(`with latest_token_balance as (
       select account_id, balance, token_id
       from token_account
       where associated is true)`);
    selectTokenBalance = `(select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select token_id, balance
            from latest_token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance)
        as token_balances`;
  }

  let balanceField = 'e.balance as balance';
  let balanceTimestampField = 'e.balance_timestamp as balance_timestamp';
  let entityTable;
  let orderClause;
  let whereClause;

  if (needHistoricalBalanceInfo) {
    if (accountBalanceQuery.query) {
      balanceField = `${accountBalanceQuery.query} as balance`;
      balanceTimestampField = `$${accountBalanceQuery.timestampParamIndex} as balance_timestamp`;
    }

    entityTable = `(
        select *
        from ${Entity.tableName} as e
        where ${whereCondition}
        union all
        select *
        from ${Entity.historyTableName} as e
        where ${whereCondition}
        order by ${Entity.TIMESTAMP_RANGE} desc limit 1
      )`;
```

**File:** rest/accounts.js (L396-396)
```javascript
const getOneAccount = async (req, res) => {
```

**File:** rest/accounts.js (L460-464)
```javascript
    } else {
      // force the query to union entity and entity history in case a valid balance snapshot is not found, so the balance
      // and its timestamp can be returned from the union
      accountBalanceQuery.forceUnionEntityHistory = true;
      tokenBalanceQuery.query = '';
```

**File:** rest/accounts.js (L487-495)
```javascript
  const entityPromise = pool.queryQuietly(entityQuery, entityParams);

  // Add the account id path parameter as a query filter for the transactions handler
  filters.push({key: filterKeys.ACCOUNT_ID, operator: opsMap.eq, value: encodedId});
  const transactionsPromise = includeTransactions
    ? transactions.doGetTransactions(filters, req, timestampRange)
    : emptyTransactionsPromise;

  const [entityResults, transactionResults] = await Promise.all([entityPromise, transactionsPromise]);
```

**File:** rest/balances.js (L189-192)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length === 0) {
    return {};
  }
```

**File:** rest/transactions.js (L483-483)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
```

**File:** rest/transactions.js (L662-662)
```javascript
  return pool.queryQuietly(query, params);
```

**File:** rest/transactions.js (L695-705)
```javascript
const doGetTransactions = async (filters, req, timestampRange) => {
  const {
    limit,
    order,
    nextTimestamp,
    rows: payerAndTimestamps,
  } = await getTransactionTimestamps(filters, timestampRange);

  const loader = (keys) => getTransactionsDetails(keys, order).then((result) => formatTransactionRows(result.rows));

  const transactions = await cache.get(payerAndTimestamps, loader, keyMapper);
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
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
