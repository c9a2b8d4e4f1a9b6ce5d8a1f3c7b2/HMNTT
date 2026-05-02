### Title
O(limit) Correlated Subquery Amplification in `/api/v1/balances` with Timestamp Filter

### Summary
When a timestamp filter is supplied to `GET /api/v1/balances`, `getBalancesQuery` embeds the result of `getTokenBalanceSubQuery` as a scalar correlated subquery in the SELECT clause, referencing `ab.account_id` from the outer row. PostgreSQL executes this subquery once per outer row, so a single unauthenticated request with `limit=100` (the default maximum) causes up to 100 independent `token_balance` table scans. Concurrent attackers multiply this load linearly with no per-user throttle.

### Finding Description
**Code path:**

`rest/balances.js` lines 113–132 — when `tsQuery` is truthy (any `timestamp=` parameter), `getBalancesQuery` is called.

`rest/balances.js` lines 199–218 — `getBalancesQuery` inlines `getTokenBalanceSubQuery(...)` directly into the SELECT list:
```sql
select distinct on (account_id)
  ab.account_id, ab.balance,
  ?::bigint as consensus_timestamp,
  (<tokenBalanceSubQuery>) as token_balances   -- ← correlated scalar subquery
from account_balance ab
...
limit <N>
```

`rest/balances.js` lines 294–306 — `getTokenBalanceSubQuery` produces:
```sql
select json_agg(...)
from (
  select distinct on (token_id) token_id, balance
  from token_balance tb
  where tb.account_id = ab.account_id          -- ← outer correlation
    and tb.consensus_timestamp >= ? and tb.consensus_timestamp <= ?
  order by token_id <order>, consensus_timestamp desc
  limit 50                                     -- tokenBalanceLimit.multipleAccounts
) as account_token_balance
```

`ab.account_id` is a different value for every outer row (enforced by `distinct on (account_id)`), so PostgreSQL's subquery memoization never fires. The subquery executes exactly once per outer row.

**Root cause:** The subquery is placed in the SELECT clause rather than being pre-joined or materialised as a CTE. The correlation variable (`ab.account_id`) is unique per row, defeating any plan-level caching.

**Limit enforcement** (`rest/utils.js` lines 544–553): the limit is capped at `responseLimit.max`, which defaults to **100** per `rest/__tests__/config.test.js` line 324. Any unauthenticated caller may request `limit=100`.

**Trigger condition:** any valid `timestamp=` value (e.g. `timestamp=lte:9999999999.999999999`) satisfies the `if (tsQuery)` branch and routes through `getBalancesQuery`.

### Impact Explanation
Each request with `limit=100` and a timestamp filter issues **100 independent index scans** against the `token_balance` historical table (which grows unboundedly over time). With `tokenBalance.multipleAccounts=50`, each scan reads up to 50 rows. A single attacker sending requests in a tight loop saturates DB connection slots and I/O. With N concurrent attackers the DB load scales as 100 × N subquery executions per second. The `account_balance` outer query also scans a historical partitioned table, compounding the cost. The result is degraded or unavailable service for all users of the mirror node REST API, which is a public-facing read API for the Hedera/Hiero network.

### Likelihood Explanation
The endpoint is unauthenticated and publicly documented. The only precondition is knowledge of any valid timestamp value (trivially obtained from any prior API response). The attack is stateless, requires no account, no tokens, and no special knowledge. It is trivially scriptable with a single `curl` command repeated in a loop. The `statementTimeout` in `db.pool` config provides a last-resort kill switch but does not prevent the DB from accepting and beginning to execute many concurrent expensive queries before the timeout fires.

### Recommendation
1. **Materialise token balances as a lateral join or CTE** instead of a correlated scalar subquery, so the planner can execute a single hash/merge join rather than N index lookups.
2. **Apply a per-IP or global request rate limit** on the `/api/v1/balances` endpoint, especially when a timestamp filter is present.
3. **Reduce `response.limit.max`** for the timestamp-filtered code path, or add a separate, lower cap for historical balance queries.
4. **Set an aggressive `statement_timeout`** at the DB session level for the REST API role to bound worst-case query duration.

### Proof of Concept
```bash
# Single high-cost request (triggers 100 correlated subqueries)
curl "https://<mirror-node>/api/v1/balances?timestamp=lte:9999999999.999999999&limit=100"

# Amplified DoS: run in parallel from multiple clients
for i in $(seq 1 50); do
  curl -s "https://<mirror-node>/api/v1/balances?timestamp=lte:9999999999.999999999&limit=100" &
done
wait
# Each of the 50 concurrent requests triggers 100 token_balance subquery executions
# = 5,000 independent DB scans per wave, repeatable with no authentication
```

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest/balances.js (L199-217)
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
