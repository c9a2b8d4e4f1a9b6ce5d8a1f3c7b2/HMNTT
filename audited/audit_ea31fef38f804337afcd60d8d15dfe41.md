### Title
Unauthenticated FULL OUTER JOIN + Dual Transaction Table JOIN Triggered via `account.id` + `result=success` + `type=credit` in `getTransactions()`

### Summary
Any unauthenticated external user can send a single HTTP GET request to `/api/v1/transactions` with the query parameters `account.id`, `result=success`, and `type=credit` to force `getTransactionTimestampsQuery()` into its most expensive execution branch: a FULL OUTER JOIN between two subqueries, each of which independently JOINs the `transaction` table. No authentication, privilege, or special knowledge is required. The server has no per-IP rate limiting, and the `limit` cap only restricts result rows, not query cost.

### Finding Description

**Exact code path:**

`getTransactions()` (line 671) → `doGetTransactions()` → `getTransactionTimestamps()` (line 451) → `getTransactionTimestampsQuery()` (line 500).

**Filter parsing in `extractSqlFromTransactionsRequest()` (lines 375–443):**

- `account.id=0.0.X` → `accountQuery = "ctl.entity_id = $1"` (non-empty) [1](#0-0) 
- `result=success` → `resultTypeQuery = "t.result in (...)"` (non-empty) [2](#0-1) 
- `type=credit` → `creditDebitQuery = "ctl.amount > 0"` (non-empty) [3](#0-2) 

(`CREDIT_TYPE` maps to URL param `type`, confirmed at `constants.js` line 31.) [4](#0-3) 

**Branch selection in `getTransactionTimestampsQuery()` (lines 555–590):**

Line 555: `if (creditDebitQuery || accountQuery)` → **TRUE** — both are set. [5](#0-4) 

Both `cryptoTransferQuery` and `tokenTransferQuery` are built via `getTransferDistinctTimestampsQuery()`. Because `resultTypeQuery` is non-empty, line 339–342 activates the `joinClause`:

```
join transaction as t using (consensus_timestamp, payer_account_id)
``` [6](#0-5) 

This means **each** of the two subqueries independently JOINs the full `transaction` table.

Line 580: `if (creditDebitQuery)` → **TRUE** — returns the FULL OUTER JOIN path: [7](#0-6) 

```sql
select coalesce(ctl.consensus_timestamp, ttl.consensus_timestamp) ...
from (<crypto_transfer JOIN transaction>) as ctl
     full outer join (<token_transfer JOIN transaction>) as ttl
       on ctl.consensus_timestamp = ttl.consensus_timestamp
order by consensus_timestamp DESC
limit $N
```

The `limit $N` only restricts the final result set; PostgreSQL must still materialize both inner subqueries (each scanning `crypto_transfer`/`token_transfer` joined to `transaction`) before the outer FULL OUTER JOIN and ORDER BY can be resolved.

**Why existing checks are insufficient:**

1. `authHandler` (server.js line 86) only sets a custom response `limit` for authenticated users; it does **not** block or throttle unauthenticated requests. [8](#0-7) 
2. No rate-limiting middleware is registered in `server.js` for the `/api/v1/transactions` route. [9](#0-8) 
3. `statement_timeout` in `dbpool.js` (line 15) is a config-dependent value that may be unset or set high; even when set, each request still consumes DB CPU/IO until the timeout fires, and the attacker can fire requests in parallel up to `pool.max` connections. [10](#0-9) 
4. `responseLimit.max` caps the number of returned rows, not the query scan cost. [11](#0-10) 

### Impact Explanation

An attacker can saturate the PostgreSQL connection pool and exhaust DB CPU/IO by sending concurrent requests that each force a FULL OUTER JOIN across `crypto_transfer JOIN transaction` and `token_transfer JOIN transaction`. On a mainnet mirror node with hundreds of millions of rows in these tables, each such query can run for seconds to minutes. With `pool.max` concurrent connections, the DB becomes unresponsive to all other API consumers. This is a griefing/DoS with no economic cost to the attacker and no on-chain footprint.

### Likelihood Explanation

The attack requires zero authentication, zero tokens, and zero on-chain activity. The three query parameters (`account.id`, `result`, `type`) are all documented public API parameters. Any script-kiddie with `curl` or a simple loop can trigger this. The combination is not exotic — it is a natural query a legitimate user might also issue, making it impossible to block by parameter blacklisting alone.

### Recommendation

1. **Add per-IP rate limiting** (e.g., `express-rate-limit`) on the `/api/v1/transactions` route, especially for unauthenticated callers.
2. **Enforce a mandatory `statement_timeout`** in `dbpool.js` that is not overridable by config omission (e.g., default to 10 seconds).
3. **Require at least one selective filter** (e.g., a narrow timestamp range or a specific `account.id`) when `creditDebitQuery` and `resultTypeQuery` are both set, to ensure the planner can use indexes rather than full scans.
4. **Limit concurrent unauthenticated DB connections** by reserving a portion of `pool.max` for authenticated users.

### Proof of Concept

```bash
# Single expensive request (no credentials required)
curl "https://<mirror-node-host>/api/v1/transactions?account.id=0.0.1&result=success&type=credit"

# Parallel flood to exhaust DB pool
for i in $(seq 1 50); do
  curl -s "https://<mirror-node-host>/api/v1/transactions?account.id=0.0.${i}&result=success&type=credit" &
done
wait
```

Each request triggers the FULL OUTER JOIN path at `rest/transactions.js` lines 583–590, with each subquery performing a JOIN to the `transaction` table (lines 339–342). No authentication header is needed. The server will accept all requests (server.js line 132) and forward them to the DB pool. [12](#0-11)

### Citations

**File:** rest/transactions.js (L339-342)
```javascript
  const joinClause =
    (resultTypeQuery || transactionTypeQuery) &&
    `join ${Transaction.tableName} as ${Transaction.tableAlias}
      using (${Transaction.CONSENSUS_TIMESTAMP}, ${Transaction.PAYER_ACCOUNT_ID})`;
```

**File:** rest/transactions.js (L390-395)
```javascript
      case constants.filterKeys.ACCOUNT_ID:
        if (operator === utils.opsMap.eq) {
          accountIdEqValues.push(value);
        } else {
          accountConditions.push(`ctl.entity_id${operator}$${params.push(value)}`);
        }
```

**File:** rest/transactions.js (L421-424)
```javascript
  if (lastCreditDebitValue) {
    const operator = lastCreditDebitValue.toLowerCase() === constants.cryptoTransferType.CREDIT ? '>' : '<';
    creditDebitQuery = `ctl.amount ${operator} 0`;
  }
```

**File:** rest/transactions.js (L426-429)
```javascript
  if (resultType) {
    const operator = resultType === constants.transactionResultFilter.SUCCESS ? 'in' : 'not in';
    resultTypeQuery = `t.result ${operator} (${utils.resultSuccess})`;
  }
```

**File:** rest/transactions.js (L555-555)
```javascript
  if (creditDebitQuery || accountQuery) {
```

**File:** rest/transactions.js (L580-590)
```javascript
    if (creditDebitQuery) {
      // credit/debit filter applies to crypto_transfer.amount and token_transfer.amount, a full outer join is needed to get
      // transactions that only have a crypto_transfer or a token_transfer
      return `
          select coalesce(ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
                 coalesce(ctl.payer_account_id, ttl.payer_account_id)       as payer_account_id
          from (${cryptoTransferQuery}) as ctl
                   full outer join (${tokenTransferQuery}) as ttl
                                   on ctl.consensus_timestamp = ttl.consensus_timestamp
          order by consensus_timestamp ${order}
              ${limitQuery}`;
```

**File:** rest/constants.js (L31-31)
```javascript
  CREDIT_TYPE: 'type',
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

**File:** rest/server.js (L132-132)
```javascript
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```
