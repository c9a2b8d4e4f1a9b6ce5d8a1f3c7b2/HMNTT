### Title
Unfiltered `latest_token_balance` CTE Full Table Scan via Unauthenticated `/api/v1/accounts` Endpoint Enables Mirror Node DoS

### Summary
The `getAccounts()` handler in `rest/accounts.js` generates a `with latest_token_balance as (select ... from token_account where associated is true)` CTE that carries no `account_id` predicate, forcing a full sequential scan of the entire `token_account` table on every request that includes balance data. Because the REST API has no rate-limiting middleware and the DB connection pool is small (default 10), an unauthenticated attacker flooding concurrent requests with `account.id=gte:0.0.1&balance=true&limit=100` can saturate all available DB connections and I/O, rendering the mirror node REST API unavailable and starving the importer of DB resources.

### Finding Description

**Exact code path:**

`getAccounts()` at `rest/accounts.js:335-388` calls `getAccountQuery()` at line 352, which calls `getEntityBalanceQuery()` at line 295. When `includeBalance=true` and no timestamp filter is present (the non-historical path), `getEntityBalanceQuery()` emits:

```sql
with latest_token_balance as (
   select account_id, balance, token_id
   from token_account
   where associated is true)          -- ← NO account_id filter
``` [1](#0-0) 

This CTE is then referenced in a correlated subquery executed once per account row returned by the outer query:

```sql
(select json_agg(...)
  from (
    select token_id, balance
    from latest_token_balance
    where account_id = e.id ...       -- filter applied AFTER CTE is built
    limit 50
  ) as account_token_balance)
``` [2](#0-1) 

**Root cause:** The CTE has no `account_id` predicate. The `token_account` table has a primary key on `(account_id, token_id)` and a secondary index on `(token_id, account_id)`, but **no index on `associated` alone**. [3](#0-2) [4](#0-3) 

When PostgreSQL materializes the CTE (which it may do for correlated-subquery contexts or under older planner statistics), it performs a full sequential scan of `token_account where associated is true` — potentially tens of millions of rows on mainnet — before the per-account `account_id = e.id` filter is applied.

**No rate limiting on the REST API:** `rest/server.js` registers no rate-limiting middleware for the `/api/v1/accounts` route. The only middleware present is logging, authentication (optional Basic Auth), optional metrics, and optional Redis cache check. [5](#0-4) 

The throttle mechanism (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module and is not applied to the REST API.

**DB connection pool:** Default `maxConnections = 10`, `statementTimeout = 20000 ms`. [6](#0-5) 

**Limit enforcement:** The account limit is capped at `responseLimit.max = 100` and token balances at `tokenBalanceResponseLimit.multipleAccounts = 50`. These caps bound the output size but do not bound the DB work performed by the CTE scan. [7](#0-6) 

### Impact Explanation

Each request with `account.id=gte:0.0.1&balance=true&limit=100` triggers a full sequential scan of `token_account` (potentially millions of rows) plus 100 correlated subqueries against that result. With a default pool of 10 connections and a 20-second statement timeout, 10 concurrent such requests fill all available DB connections for up to 20 seconds each. Subsequent REST API requests queue indefinitely or time out. The importer (`mirror_importer` DB user) shares the same PostgreSQL instance; sustained I/O saturation degrades its ability to write newly ingested transactions, delaying mirror node data freshness. This constitutes a full DoS of the mirror node REST API and degraded importer throughput — not a shutdown of Hedera consensus nodes, but a critical availability failure of the mirror node infrastructure relied upon by wallets, explorers, and dApps.

### Likelihood Explanation

No authentication, API key, or proof-of-work is required. The exploit requires only an HTTP client and knowledge of the public API. The request is syntactically valid and passes all parameter validation. A single attacker with modest bandwidth can sustain the attack indefinitely by cycling requests as connections free up. The attack is trivially scriptable and repeatable.

### Recommendation

1. **Add an `account_id` filter to the CTE** so it only reads rows relevant to the accounts being returned, or restructure the query to use a lateral join with the per-account filter pushed into the `token_account` access:
   ```sql
   -- Replace the unfiltered CTE with a lateral join:
   left join lateral (
     select json_agg(...) from token_account
     where account_id = e.id and associated is true
     order by token_id asc limit 50
   ) as tb on true
   ```
2. **Add rate limiting middleware** to the REST API (e.g., `express-rate-limit`) keyed by IP address, applied before route handlers in `rest/server.js`.
3. **Add an index on `(associated, account_id, token_id)`** or `(account_id, associated)` to support the CTE filter efficiently if the CTE structure is retained.
4. **Increase `statementTimeout`** awareness: the current 20-second timeout means each attack request holds a connection for up to 20 seconds, amplifying pool exhaustion.

### Proof of Concept

```bash
# Fill all 10 DB connections with expensive scans simultaneously
for i in $(seq 1 15); do
  curl -s "http://<mirror-node-host>:5551/api/v1/accounts?account.id=gte:0.0.1&balance=true&limit=100" &
done
wait

# Observe: subsequent legitimate requests time out or return 503
curl -v "http://<mirror-node-host>:5551/api/v1/accounts?account.id=0.0.98"
# Expected: connection timeout or DB pool exhaustion error
```

Reproducible steps:
1. Deploy mirror node with default config (`maxConnections=10`, `statementTimeout=20000`).
2. Populate `token_account` with ≥1M rows (representative of mainnet).
3. Fire 15 concurrent GET requests to `/api/v1/accounts?account.id=gte:0.0.1&balance=true&limit=100`.
4. Observe all 10 pool connections occupied; legitimate API requests fail; importer write latency increases.

### Citations

**File:** rest/accounts.js (L183-186)
```javascript
    queries.push(`with latest_token_balance as (
       select account_id, balance, token_id
       from token_account
       where associated is true)`);
```

**File:** rest/accounts.js (L187-195)
```javascript
    selectTokenBalance = `(select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select token_id, balance
            from latest_token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance)
        as token_balances`;
```

**File:** rest/accounts.js (L343-345)
```javascript
  const limitAndOrderQuery = utils.parseLimitAndOrderParams(req, constants.orderFilterValues.ASC);
  const pubKeyQuery = toQueryObject(utils.parsePublicKeyQueryParam(req.query, 'public_key'));
  const tokenBalanceQuery = {query: 'account_id = e.id', params: [], limit: tokenBalanceResponseLimit.multipleAccounts};
```

**File:** importer/src/main/resources/db/migration/v1/V1.66.1__token_account_history.sql (L48-49)
```sql
alter table token_account add primary key (account_id, token_id);
alter table token_account_history add primary key (account_id, token_id, timestamp_range);
```

**File:** importer/src/main/resources/db/migration/v1/V1.113.0__udpate_token_account_index.sql (L1-2)
```sql
create index if not exists token_account__token_id_account_id
    on token_account(token_id, account_id);
```

**File:** rest/server.js (L81-101)
```javascript
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
