### Title
Unauthenticated Connection Pool Exhaustion via Sequential DB Queries in `getBalances()` with `account.publickey` + `timestamp` Filters

### Summary
When `getBalances()` receives both a `timestamp` and `account.publickey` query parameter, it issues three sequential `await pool.queryQuietly()` calls — `getAccountBalanceTimestampRange`, `getAccountIdsByPublicKey`, and the main balance query — each acquiring a connection from the shared pool. With a default pool of only 10 connections, no application-level rate limiting on the REST API, and a 20-second statement timeout, an attacker sending as few as 10 concurrent crafted requests can sustain full pool exhaustion, causing all REST API endpoints (not just `/balances`) to queue or fail for the duration of the attack.

### Finding Description

**Exact code path** (`rest/balances.js`, lines 113–153):

```
if (tsQuery) {
  const tsQueryResult = await getTsQuery(tsQuery, tsParams);      // Query 1: pool.queryQuietly (line 189)
  ...
  const accountIdsQuery = await getAccountIdsByPublicKey(...);    // Query 2: pool.queryQuietly (line 66)
  ...
  [sqlQuery, tsParams] = await getBalancesQuery(...);
}
const result = await pool.queryQuietly(pgSqlQuery, sqlParams);    // Query 3: pool.queryQuietly (line 153)
``` [1](#0-0) 

Each `pool.queryQuietly()` call acquires a connection, executes the query, and releases it. Connections are held sequentially (not simultaneously per request), but with N concurrent requests each making 3 sequential queries, the pool is occupied for 3× the duration of a single-query endpoint. This dramatically increases the window during which all pool slots are busy.

**Root cause**: The three-query code path is only triggered when both `tsQuery` and `pubKeyQuery` are non-empty (lines 113, 119). There is no concurrency cap, semaphore, or rate limiter in the REST API middleware stack. [2](#0-1) 

**Pool configuration** (`rest/dbpool.js`): `max` is set from `config.db.pool.maxConnections`, which defaults to **10** connections with a `statementTimeout` of **20,000 ms** and `connectionTimeoutMillis` of **20,000 ms**. [3](#0-2) [4](#0-3) 

**No rate limiting on the REST API**: `server.js` registers only `authHandler`, `metricsHandler`, and cache middleware — no throttle or concurrency limiter. The throttle infrastructure found (`ThrottleConfiguration`, `ThrottleManagerImpl`) is exclusively in the `web3` Java module and does not apply to the Node.js REST API. [5](#0-4) 

### Impact Explanation
The shared `pool` object is global and used by every REST endpoint. Exhausting it blocks all API routes — accounts, transactions, tokens, etc. — not just `/balances`. With `connectionTimeoutMillis = 20000`, clients waiting for a connection will hang for up to 20 seconds before receiving an error, compounding the degradation. Because the mirror node REST API is the primary read interface for network participants querying state, sustained unavailability degrades any downstream service or tooling that depends on it.

### Likelihood Explanation
The attack requires zero privileges — `account.publickey` and `timestamp` are publicly documented, unauthenticated query parameters. A valid public key can be obtained from any prior transaction on the network. Sending 10–15 concurrent HTTP requests is trivially achievable with `curl`, `ab`, `wrk`, or any scripting language. The attacker does not need to sustain a high request rate; because each request holds a connection for the duration of 3 sequential queries (up to 3 × 20 s = 60 s worst case under slow DB conditions), even a low-rate flood maintains exhaustion. The attack is repeatable indefinitely.

### Recommendation
1. **Add a concurrency limiter** at the Express middleware layer (e.g., `express-rate-limit` or a custom semaphore) to cap the number of simultaneous in-flight requests per IP or globally before they reach DB-touching handlers.
2. **Merge the three sequential queries into a single SQL statement** (CTE or subquery) so only one connection is acquired per request in the `tsQuery + pubKeyQuery` path.
3. **Increase the default pool size** (`maxConnections`) and document it as a tunable parameter for production deployments, or expose a per-endpoint connection budget.
4. **Add a `connectionTimeoutMillis` fast-fail** with a meaningful HTTP 503 response rather than silently queuing, so clients back off quickly.

### Proof of Concept

**Preconditions**: Mirror node REST API accessible; one valid compressed/uncompressed public key `<PUB_KEY>` known (obtainable from any account lookup); a recent valid timestamp `<TS>`.

```bash
# Send 15 concurrent requests, each triggering the 3-query path
for i in $(seq 1 15); do
  curl -s "http://<mirror-node>:5551/api/v1/balances?account.publickey=<PUB_KEY>&timestamp=lte:<TS>" &
done
wait
```

**Expected result**: After the pool of 10 connections is saturated, subsequent requests to *any* REST endpoint (e.g., `/api/v1/transactions`) return errors or hang for up to 20 seconds (`connectionTimeoutMillis`), confirming full pool exhaustion. Repeating the loop continuously sustains the outage.

### Citations

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

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```
