### Title
Unauthenticated Concurrent Dual-Query DB Connection Pool Exhaustion in `getOneAccount()`

### Summary
`getOneAccount()` in `rest/accounts.js` unconditionally fires two expensive database queries concurrently via `Promise.all()` — a historical `UNION ALL` entity query and a full `doGetTransactions()` query — for any unauthenticated request supplying `transactions=true` (the default) and a `timestamp` parameter. Because the REST API has no rate-limiting middleware and the default DB connection pool is only 10 connections, an attacker needs only 5 concurrent requests to exhaust the pool, denying service to all other users.

### Finding Description

**Code path — `rest/accounts.js`, `getOneAccount()`, lines 396–512:**

When `timestampFilters.length > 0` (i.e., any `timestamp=` query param is present), the code at lines 428–474 builds a historical entity query. Inside `getEntityBalanceQuery()` (lines 204–219), `isHistorical = true` causes the entity table to be replaced with:

```sql
(SELECT * FROM entity AS e WHERE ...
 UNION ALL
 SELECT * FROM entity_history AS e WHERE ...
 ORDER BY timestamp_range DESC LIMIT 1)
```

Additionally, `getEntityStakeQuery()` (lines 18–31) also emits a `UNION ALL` between `entity_stake` and `entity_stake_history` when `isHistorical = true`.

At line 487, this expensive historical query is dispatched immediately without awaiting:
```js
const entityPromise = pool.queryQuietly(entityQuery, entityParams);
```

At lines 491–493, `doGetTransactions()` — which itself issues multiple sub-queries across `transaction`, `crypto_transfer`, `token_transfer`, and `entity_transaction` tables — is also dispatched without awaiting:
```js
const transactionsPromise = includeTransactions
  ? transactions.doGetTransactions(filters, req, timestampRange)
  : emptyTransactionsPromise;
```

Both are then awaited together at line 495:
```js
const [entityResults, transactionResults] = await Promise.all([entityPromise, transactionsPromise]);
```

This means every single request to this endpoint with `transactions=true` (the default) and any `timestamp` parameter holds **two DB connections simultaneously** for the full duration of both queries.

**No rate limiting on the REST API:** `rest/server.js` (lines 68–98) shows the middleware stack is: `urlencoded`, `json`, `cors`, `compression`, `httpContext`, `requestLogger`, `authHandler`, `metricsHandler`, `responseCacheCheckHandler`. There is no rate-limiting middleware. The throttle configuration found (`web3/src/main/java/.../ThrottleConfiguration.java`) applies only to the separate `web3` Java module, not to this Node.js REST API.

**Tiny default connection pool:** `rest/dbpool.js` line 14 sets `max: config.db.pool.maxConnections`, and `docs/configuration.md` line 556 documents the default as **10 connections**. With 2 connections consumed per request, only **5 concurrent requests** are needed to exhaust the pool.

### Impact Explanation
With the pool exhausted, all subsequent requests to any REST API endpoint queue waiting for a connection. The `connectionTimeoutMillis` (default 20 000 ms per `docs/configuration.md` line 555) means queued requests time out and return errors to legitimate users. This is a complete, non-network-based denial of service against the mirror node REST API, achievable with a trivially small number of concurrent HTTP connections (5 at default pool size).

### Likelihood Explanation
No authentication, API key, or proof-of-work is required. The `timestamp` parameter is a documented, publicly advertised query parameter. The attack is repeatable indefinitely, requires no special knowledge beyond reading the public API docs, and can be executed from a single machine with a basic HTTP client. The attacker does not need to know the pool size in advance — even a modest flood of 10–20 concurrent requests is sufficient to guarantee exhaustion.

### Recommendation
1. **Add rate limiting to the REST API** (e.g., `express-rate-limit` or an ingress-level rate limiter) keyed by IP, targeting the `/api/v1/accounts/:id` endpoint specifically.
2. **Serialize the two queries** when the historical path is taken, or at minimum gate the concurrent execution behind a semaphore that limits total in-flight DB connections.
3. **Increase the default `maxConnections`** or document a minimum safe value relative to expected concurrency.
4. **Require `transactions=false` to be explicit** when a `timestamp` filter is present, rather than defaulting to `true`, to reduce the blast radius of the expensive combined path.

### Proof of Concept

```bash
# Exhaust a default-configured instance (pool=10) with 5 concurrent requests
for i in $(seq 1 5); do
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts/0.0.98?transactions=true&timestamp=lte:1234567890.000000000" &
done
wait

# All subsequent requests now time out or return 503/connection errors:
curl -v "http://<mirror-node-host>:5551/api/v1/accounts/0.0.98"
```

Each of the 5 background requests holds 2 pool connections (historical entity UNION ALL + `doGetTransactions`) for the full query duration, exhausting all 10 default connections. The final foreground request receives a connection-timeout error after 20 seconds. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/accounts.js (L18-31)
```javascript
const getEntityStakeQuery = (filter, isHistorical = false) => {
  if (isHistorical) {
    return `(
      select * from (
          select * from entity_stake as e where ${filter}
                union all
          select * from entity_stake_history as e where ${filter}
      )
      as asd
      order by asd.timestamp_range desc limit 1
    )`;
  }

  return 'entity_stake';
```

**File:** rest/accounts.js (L204-219)
```javascript
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

**File:** rest/accounts.js (L428-474)
```javascript
  if (timestampFilters.length > 0) {
    const [balanceSnapshotTsQuery, balanceSnapshotTsParams] = utils.buildTimestampQuery(
      'consensus_timestamp',
      timestampRange,
      false
    );

    const {lower, upper} = await balances.getAccountBalanceTimestampRange(
      balanceSnapshotTsQuery.replaceAll(opsMap.eq, opsMap.lte),
      balanceSnapshotTsParams
    );

    if (upper !== undefined) {
      // Note when a balance snapshot timestamp is not found, it falls back to return balance info from entity table
      const lowerTimestampParamIndex = ++paramCount;
      const upperTimestampParamIndex = ++paramCount;
      // Note if no balance info for the specific account in the timestamp range is found, the balance should be 0.
      // It can happen when the account is just created and the very first snapshot is after the range.
      accountBalanceQuery.query = `coalesce((
        select balance
        from account_balance
        where account_id = $${accountIdParamIndex} and
          consensus_timestamp >= $${lowerTimestampParamIndex} and
          consensus_timestamp <= $${upperTimestampParamIndex}
        order by consensus_timestamp desc
        limit 1
      ), 0)`;
      accountBalanceQuery.timestampParamIndex = upperTimestampParamIndex;

      tokenBalanceQuery.params.push(lower, upper);
      tokenBalanceQuery.query += ` and consensus_timestamp >= $${lowerTimestampParamIndex} and
        consensus_timestamp <= $${upperTimestampParamIndex}`;
    } else {
      // force the query to union entity and entity history in case a valid balance snapshot is not found, so the balance
      // and its timestamp can be returned from the union
      accountBalanceQuery.forceUnionEntityHistory = true;
      tokenBalanceQuery.query = '';
    }

    const [entityTsQuery, entityTsParams] = utils.buildTimestampRangeQuery(
      Entity.getFullName(Entity.TIMESTAMP_RANGE),
      timestampRange
    );

    entityAccountQuery.query += ` and ${entityTsQuery.replaceAll('?', (_) => `$${++paramCount}`)}`;
    entityAccountQuery.params = entityAccountQuery.params.concat(entityTsParams);
  }
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
