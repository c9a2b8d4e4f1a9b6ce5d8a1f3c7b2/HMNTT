### Title
Unbounded `latest_token_balance` CTE Full-Table Scan in `getAccounts()` Enables Unauthenticated DoS

### Summary
`getAccounts()` in `rest/accounts.js` unconditionally materializes a `with latest_token_balance` CTE that performs an unbounded full-table scan of `token_account where associated is true` on every request where `balance=true` (the default). No rate limiting exists on the REST API layer. Any unauthenticated external caller can flood this endpoint to saturate DB I/O and memory, starving legitimate gossip-related queries.

### Finding Description

**Exact code path:**

`rest/accounts.js`, `getEntityBalanceQuery()`, lines 183–186:

```javascript
queries.push(`with latest_token_balance as (
   select account_id, balance, token_id
   from token_account
   where associated is true)`);
``` [1](#0-0) 

This CTE carries **no LIMIT clause and no `account_id` predicate**. It reads every row in `token_account` where `associated = true` — the entire live token-association table — regardless of any query parameter supplied by the caller.

The CTE is then consumed inside a correlated scalar subquery that runs once per returned entity row:

```javascript
selectTokenBalance = `(select json_agg(...)
      from (
        select token_id, balance
        from latest_token_balance
        where ${tokenBalanceQuery.query}   -- account_id = e.id
        order by token_id ${order}
        limit ${tokenBalanceQuery.limit}   -- 50
      ) as account_token_balance)
    as token_balances`;
``` [2](#0-1) 

Because the CTE is referenced inside a correlated subquery that executes per row, PostgreSQL will materialize it (pre-12 always; post-12 when the planner judges it beneficial for repeated access). Materialization loads **all** associated token-account rows into the DB work-mem/temp-file space before the outer query even begins filtering.

**Root cause / failed assumption:** The code assumes the outer `WHERE e.balance …` / `LIMIT` clause will bound the cost of the CTE. It does not — the CTE is evaluated independently and in full before any outer predicate is applied.

**Note on the `account.balance` filter specifically:** The `account.balance` filter (parsed via `parseBalanceQueryParam` into `e.balance OP ?`) is applied only to the outer `entity` table scan, not to the CTE. It does not change the CTE's size. The CTE is always a full scan. The filter is therefore irrelevant to the CTE cost — the DoS is triggered by any call with `balance=true` (the default). [3](#0-2) 

**No rate limiting on the REST API:** The `authHandler` middleware only sets a custom response-row limit for authenticated users; it does not throttle request frequency. [4](#0-3) 

The throttling infrastructure (`ThrottleManagerImpl`, `ThrottleConfiguration`) exists only in the `web3` module (contract calls), not in the REST API. [5](#0-4) 

A `statement_timeout` is configurable at the pool level: [6](#0-5) 

but its default value is not enforced in code and is operator-dependent; it does not constitute a reliable mitigation.

### Impact Explanation

On a production Hedera network the `token_account` table contains tens of millions of rows (every token association ever created). Each `GET /api/v1/accounts` call with `balance=true` forces PostgreSQL to read and potentially materialize this entire dataset. Concurrent flooding of this endpoint by a single unauthenticated attacker can:

- Exhaust PostgreSQL `work_mem` / spill to disk, degrading all concurrent queries
- Saturate I/O bandwidth shared with the consensus-gossip ingestion pipeline
- Cause connection-pool exhaustion in the mirror-node REST service, making the node unresponsive to legitimate clients and to gossip-related read queries

Severity: **High** (availability impact on a public, unauthenticated endpoint with no compensating control).

### Likelihood Explanation

- No authentication required; the endpoint is public.
- No per-IP or per-endpoint rate limiting exists in the REST layer.
- The default value of `balance` is `true`, so no special parameter crafting is needed.
- A single attacker with a modest HTTP client can issue hundreds of concurrent requests per second.
- The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add a `LIMIT` to the CTE** or, preferably, push the `account_id = e.id` predicate inside the CTE so it becomes a correlated lookup rather than a full scan:
   ```sql
   -- Instead of a global CTE, use a lateral subquery scoped to each account
   lateral (
     select json_agg(...) from token_account
     where account_id = e.id and associated is true
     order by token_id asc limit 50
   ) as tb
   ```
2. **Implement request-rate limiting** on the REST API layer (e.g., express-rate-limit per IP) analogous to the `ThrottleManagerImpl` already present in the web3 module.
3. **Set a mandatory, low `statement_timeout`** (e.g., 5 s) in the pool configuration to bound runaway queries.
4. **Consider caching** the token-balance CTE result with a short TTL (Redis cache is already wired in `server.js`) to avoid repeated full scans.

### Proof of Concept

```bash
# No credentials required. Flood with concurrent requests.
# On a network with millions of token associations this will
# cause DB memory pressure and degrade all concurrent queries.

for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/accounts" &
done
wait

# Variant using account.balance filter (irrelevant to CTE cost,
# but confirms no special privilege is needed):
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/accounts?account.balance=gte:0" &
done
wait
```

Each request causes PostgreSQL to execute:
```sql
with latest_token_balance as (
  select account_id, balance, token_id
  from token_account
  where associated is true   -- no limit, full scan
)
select ...
from entity as e
...
limit 100;
```

Observed effect: DB CPU/IO spikes to 100 %, `pg_stat_activity` shows many long-running `latest_token_balance` materializations, and response latency for all other endpoints (including gossip-related reads) degrades sharply.

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

**File:** rest/accounts.js (L341-345)
```javascript
  const balanceQuery = toQueryObject(utils.parseBalanceQueryParam(req.query, 'e.balance'));
  const includeBalance = getBalanceParamValue(req.query);
  const limitAndOrderQuery = utils.parseLimitAndOrderParams(req, constants.orderFilterValues.ASC);
  const pubKeyQuery = toQueryObject(utils.parsePublicKeyQueryParam(req.query, 'public_key'));
  const tokenBalanceQuery = {query: 'account_id = e.id', params: [], limit: tokenBalanceResponseLimit.multipleAccounts};
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

**File:** rest/server.js (L82-98)
```javascript
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

**File:** rest/dbpool.js (L15-15)
```javascript
  statement_timeout: config.db.pool.statementTimeout,
```
