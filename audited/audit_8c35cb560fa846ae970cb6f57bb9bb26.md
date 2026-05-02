### Title
Unauthenticated Timestamp Filter Triggers Correlated Subquery Amplification in `/api/v1/balances`

### Summary
Any unauthenticated user can supply a `timestamp` query parameter to `/api/v1/balances`, which routes execution through `getTokenBalanceSubQuery()` instead of the cheaper `getTokenAccountBalanceSubQuery()`. The result is a correlated scalar subquery — containing `distinct on (token_id)` with a sort — that PostgreSQL executes once for every row the outer query returns, multiplying database work by up to the configured `limit` maximum (default 100) per request.

### Finding Description
**Code path:**

`getBalances()` (`rest/balances.js:113`) checks `if (tsQuery)`. When any `timestamp` parameter is present in the request, it calls `getTsQuery()` then `getBalancesQuery()`:

```
rest/balances.js:113  if (tsQuery) {
rest/balances.js:124    [sqlQuery, tsParams] = await getBalancesQuery(...)
```

`getBalancesQuery()` (line 199–218) calls `getTokenBalanceSubQuery()` (line 200) and inlines its return value as a scalar subquery in the SELECT list (line 212):

```js
// rest/balances.js:207-216
select distinct on (account_id)
  ab.account_id,
  ab.balance,
  ?::bigint as consensus_timestamp,
  (${tokenBalanceSubQuery}) as token_balances   -- correlated subquery here
from account_balance ab
...
limit <limit>
```

`getTokenBalanceSubQuery()` (lines 294–306) produces:

```sql
select json_agg(...)
from (
  select distinct on (token_id) token_id, balance
  from token_balance tb
  where tb.account_id = ab.account_id          -- correlated on outer ab.account_id
    and tb.consensus_timestamp >= ? and tb.consensus_timestamp <= ?
  order by token_id <order>, consensus_timestamp desc
  limit 50                                     -- tokenBalanceLimit.multipleAccounts
) as account_token_balance
```

The `where tb.account_id = ab.account_id` reference to the outer `ab` alias makes this a **correlated subquery**. PostgreSQL must re-execute it for every row the outer query produces. The outer query is bounded by `limit` (default 25, max 100 per `rest/__tests__/config.test.js:324`). Each inner execution performs a `distinct on (token_id)` with `order by token_id, consensus_timestamp desc`, requiring a sort or index scan over the `token_balance` partition range.

**Root cause:** The timestamp-filtered code path unconditionally uses a correlated subquery against the historical `token_balance` table. The non-timestamp path (line 137) uses `getTokenAccountBalanceSubQuery()` which queries the `token_account` table without a correlated sort. No rate-limiting or query-cost guard is applied before executing the assembled SQL.

**Exploit flow:**
1. Attacker sends `GET /api/v1/balances?timestamp=lte:9999999999&limit=100` — no credentials needed.
2. `tsQuery` is non-empty → `getBalancesQuery()` is called.
3. The outer query returns up to 100 `account_balance` rows.
4. For each of those 100 rows, PostgreSQL executes the inner `distinct on (token_id)` subquery against `token_balance`, scanning up to 50 rows per account per the inner `limit`.
5. Attacker repeats in a tight loop from multiple clients.

**Why existing checks are insufficient:**
- The `limit` cap (100) bounds work *per request* but does not prevent amplification across concurrent requests.
- `tokenBalanceLimit.multipleAccounts = 50` bounds the inner result set but not the number of inner executions.
- No rate-limiting, query timeout, or cost-based rejection is visible in `balances.js` or the surrounding middleware for this endpoint.

### Impact Explanation
Each timestamp-filtered request causes up to 100 correlated subquery executions, each involving a sort over a time-partitioned `token_balance` table. An attacker sending a sustained stream of such requests (trivially parallelisable) can saturate PostgreSQL I/O and CPU, increasing query latency for all concurrent users. The impact is service degradation (throughput reduction, increased p99 latency) rather than data loss or financial harm — consistent with the "griefing" classification.

### Likelihood Explanation
The `timestamp` parameter is publicly documented and accepted without authentication. The exploit requires only an HTTP client and knowledge of the public API. It is trivially repeatable and scriptable. No special account, token, or on-chain state is required. The attacker needs no economic stake.

### Recommendation
1. **Materialise the subquery as a lateral join or CTE** so the planner can choose a hash/merge join rather than a nested-loop correlated execution.
2. **Apply a statement timeout** (e.g., `SET LOCAL statement_timeout = '5s'`) for this endpoint before executing the assembled query.
3. **Add per-IP or per-endpoint rate limiting** at the API gateway or middleware layer for the `/api/v1/balances` route when a `timestamp` filter is present.
4. **Consider caching** the resolved timestamp range (`getAccountBalanceTimestampRange`) and the resulting balance snapshot, since historical snapshots are immutable.

### Proof of Concept
```bash
# Single amplified request (100 correlated subquery executions)
curl "https://<mirror-node>/api/v1/balances?timestamp=lte:9999999999&limit=100"

# Sustained griefing loop (no credentials required)
while true; do
  curl -s "https://<mirror-node>/api/v1/balances?timestamp=lte:9999999999&limit=100" &
done
```

Observe PostgreSQL `pg_stat_activity` showing repeated `distinct on (token_id)` plans and rising `blks_read`/`blks_hit` on the `token_balance` table, with concurrent legitimate queries experiencing increased latency. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/balances.js (L113-131)
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
