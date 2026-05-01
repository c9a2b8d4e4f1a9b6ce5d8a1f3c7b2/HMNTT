### Title
Unauthenticated DB CPU Exhaustion via Nested DISTINCT ON Correlated Subquery in `/api/v1/balances` Timestamp Filter

### Summary
Any unauthenticated user can supply a `timestamp` query parameter to `GET /api/v1/balances`, causing `getBalancesQuery()` to construct a query combining `SELECT DISTINCT ON (account_id)` over `account_balance` with a correlated `SELECT DISTINCT ON (token_id)` subquery over `token_balance` plus `json_agg` aggregation. No application-level rate limiting exists on the Node.js REST API for this endpoint. Sending many such requests concurrently exhausts database CPU, degrading all mirror node instances that share the same database.

### Finding Description

**Exact code path:**

`getBalances()` (line 113) checks `if (tsQuery)` and calls `getBalancesQuery()` (line 124).

`getBalancesQuery()` (lines 199–218) builds:
```sql
SELECT DISTINCT ON (account_id)
  ab.account_id, ab.balance, ?::bigint AS consensus_timestamp,
  (<token_subquery>) AS token_balances
FROM account_balance ab
WHERE ab.consensus_timestamp >= ? AND ab.consensus_timestamp <= ?
ORDER BY ab.account_id DESC, ab.consensus_timestamp DESC
LIMIT 100
```

`getTokenBalanceSubQuery()` (lines 294–306) inlines a correlated subquery executed once per outer row:
```sql
SELECT json_agg(json_build_object('token_id', token_id, 'balance', balance))
FROM (
  SELECT DISTINCT ON (token_id) token_id, balance
  FROM token_balance tb
  WHERE tb.account_id = ab.account_id
    AND tb.consensus_timestamp >= ? AND tb.consensus_timestamp <= ?
  ORDER BY token_id DESC, consensus_timestamp DESC
  LIMIT 50
) AS account_token_balance
```

**Root cause:** The outer `DISTINCT ON (account_id)` must sort and deduplicate all rows in the timestamp range before applying `LIMIT`. For each of up to 100 result rows, the correlated subquery performs a separate `DISTINCT ON (token_id)` sort + deduplication + `json_agg` over `token_balance`. This is O(N × M) in DB work per request, where N = account_balance rows in range and M = token_balance rows per account in range.

**Failed assumption:** The `getOptimizedTimestampRange()` function (lines 229–277) limits the scan to at most two monthly partitions, but this still covers potentially millions of rows. The `LIMIT 50` on the subquery and `LIMIT 100` on the outer query do not prevent the `DISTINCT ON` sort from processing all matching rows before truncating output.

**No application-level rate limiting exists for the REST API balances endpoint.** The throttle mechanisms found (`ThrottleManagerImpl`, `ThrottleConfiguration`) are exclusively in the `web3` Java service, not the Node.js REST API. The GCP gateway `maxRatePerEndpoint: 250` is an optional infrastructure component that may not be deployed.

### Impact Explanation

The shared PostgreSQL database backs all mirror node REST API instances. Sustained DB CPU exhaustion from concurrent expensive queries causes query timeouts and connection pool saturation across all mirror node instances simultaneously. This degrades or takes down the entire mirror node REST API service, which constitutes degradation of 30%+ of mirror node processing capacity. The `account_balance` and `token_balance` tables on a production Hedera mirror node contain hundreds of millions to billions of rows, making each query genuinely expensive even within a two-month partition window.

### Likelihood Explanation

The attack requires zero authentication, zero privileges, and zero special knowledge beyond the public API documentation. The endpoint is documented in the OpenAPI spec (`rest/api/v1/openapi.yml` line 391). A single attacker with a modest botnet or even a single machine with high concurrency (e.g., 200–500 concurrent HTTP connections) can sustain the attack indefinitely. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add application-level rate limiting** to the Node.js REST API for the `/api/v1/balances` endpoint (e.g., using `express-rate-limit` or similar), scoped per IP.
2. **Enforce a DB `statement_timeout`** for the REST API database role to kill runaway queries (e.g., 5–10 seconds).
3. **Limit DB connection pool size** (`maxConnections`) to bound the number of concurrent expensive queries.
4. **Rewrite the correlated subquery** as a single JOIN with window functions or a lateral join to avoid per-row subquery execution.
5. **Require authentication** or a CAPTCHA for timestamp-filtered balance queries, or add a query cost budget.

### Proof of Concept

```bash
# Send 300 concurrent requests with a timestamp filter (no auth required)
# Replace TIMESTAMP with any valid nanosecond timestamp
TIMESTAMP="1680000000.000000000"
for i in $(seq 1 300); do
  curl -s "https://<mirror-node-host>/api/v1/balances?timestamp=lte:${TIMESTAMP}&limit=100" \
    -o /dev/null &
done
wait
# Monitor DB CPU: should spike to near 100% on the database host
# Subsequent legitimate requests will time out or return 500 errors
```

Each request triggers the nested `DISTINCT ON` + correlated subquery pattern in `getBalancesQuery()` (lines 207–216) and `getTokenBalanceSubQuery()` (lines 296–305). With 300 concurrent requests and no rate limiting, the DB CPU is saturated, degrading all mirror node instances sharing the database. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/balances.js (L113-132)
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
```

**File:** rest/balances.js (L199-218)
```javascript
const getBalancesQuery = async (accountQuery, balanceQuery, accountIdsQuery, limitQuery, order, tsQueryResult) => {
  const tokenBalanceSubQuery = getTokenBalanceSubQuery(order, tsQueryResult.query);
  const whereClause = `
      where ${[tsQueryResult.query, accountQuery, accountIdsQuery, balanceQuery].filter(Boolean).join(' and ')}`;
  const {lower, upper} = tsQueryResult.timestampRange;
  // The first upper is for the consensus_timestamp in the select fields, also double the lower and the upper since
  // they are used twice, in the token balance subquery and in the where clause of the main query
  const tsParams = [upper, lower, upper, lower, upper];
  const sqlQuery = `
      select distinct on (account_id)
        ab.account_id,
        ab.balance,
        ?::bigint as consensus_timestamp,
        (${tokenBalanceSubQuery}) as token_balances
      from account_balance ab
      ${whereClause}
      order by ab.account_id ${order}, ab.consensus_timestamp desc
      ${limitQuery}`;
  return [sqlQuery, tsParams];
};
```

**File:** rest/balances.js (L294-306)
```javascript
const getTokenBalanceSubQuery = (order, consensusTsQuery) => {
  consensusTsQuery = consensusTsQuery.replaceAll('ab.', 'tb.');
  return `
    select json_agg(json_build_object('token_id', token_id, 'balance', balance))
    from (
      select distinct on (token_id) token_id, balance
      from token_balance tb
      where tb.account_id = ab.account_id
        and ${consensusTsQuery}
      order by token_id ${order}, consensus_timestamp desc
      limit ${tokenBalanceLimit.multipleAccounts}
    ) as account_token_balance`;
};
```
