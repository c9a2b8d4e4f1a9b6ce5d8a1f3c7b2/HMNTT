### Title
Correlated Token Balance Subquery Amplification DoS in `getAccounts()`

### Summary
In `rest/accounts.js`, `getAccounts()` embeds a correlated subquery (`account_id = e.id`) inside the `SELECT` list that is re-evaluated once per outer entity row. An unauthenticated attacker can request `limit=100` (the public maximum) with no `account.id` filter, causing the database to execute the `latest_token_balance` CTE-backed correlated subquery 100 times per request — each time scanning the full materialized CTE derived from `token_account`. Flooding the endpoint with concurrent requests multiplies DB CPU and I/O load, starving legitimate queries including transaction ingestion reads.

### Finding Description

**Exact code path:**

`getAccounts()` at `rest/accounts.js:345` constructs: [1](#0-0) 

```js
const tokenBalanceQuery = {query: 'account_id = e.id', params: [], limit: tokenBalanceResponseLimit.multipleAccounts};
```

`tokenBalanceResponseLimit.multipleAccounts` defaults to **50**. [2](#0-1) 

This query object is passed to `getEntityBalanceQuery()` at `rest/accounts.js:295`. Since `getAccounts()` passes `accountBalanceQuery = undefined` (line 355), `needHistoricalBalanceInfo` is `false`, and the non-historical branch is taken: [3](#0-2) 

The generated SQL is:
```sql
with latest_token_balance as (
  select account_id, balance, token_id
  from token_account
  where associated is true          -- full table scan, no per-account filter
)
select ...,
  (select json_agg(...)
   from (
     select token_id, balance
     from latest_token_balance
     where account_id = e.id        -- CORRELATED: references outer row
     order by token_id asc
     limit 50
   ) as account_token_balance) as token_balances
from entity as e
...
order by e.id asc
limit 100                           -- attacker-controlled, capped at max
```

The `account_id = e.id` condition is a **correlated reference** to the outer query's current row. PostgreSQL must re-execute the inner subquery for every row produced by the outer query. With `limit=100`, this is **100 executions** per request.

The `latest_token_balance` CTE materializes the entire `token_account` table (filtered only by `associated is true`). In PostgreSQL 12+ the planner may inline the CTE, causing a full `token_account` scan per outer row. Even when materialized once, the correlated subquery performs a sequential scan of the materialized result for each of the 100 outer rows, since the CTE result has no index.

**Root cause:** The token balance subquery is placed in the `SELECT` list as a scalar correlated subquery rather than as a single pre-aggregated join or a lateral join with a proper index path. The `limit` on accounts (100) and the `limit` on token balances per account (50) bound the *output size* but not the *number of subquery executions*.

**Why existing checks fail:**

- `getLimitParamValue` caps the account `limit` at `responseLimit.max = 100` for unauthenticated users — this is the multiplier, not a mitigation. [4](#0-3) 
- `tokenBalanceResponseLimit.multipleAccounts = 50` limits rows *returned* per account, not executions. [5](#0-4) 
- The DB `statementTimeout` (default 10 s) limits a single query's duration but does not prevent many concurrent requests each holding a DB connection for up to 10 s.
- No rate limiting or request throttling is visible in the REST layer for this endpoint.

### Impact Explanation

On a production mirror node with millions of `token_account` rows, each `GET /api/v1/accounts?limit=100` request triggers 100 correlated subquery executions against the full `token_account` table. An attacker sending N concurrent requests causes up to `N × 100` concurrent DB scans. This exhausts the DB connection pool, saturates CPU/I/O, and delays or blocks all other queries — including those serving transaction data and the importer's write path. The impact is a practical denial-of-service against the mirror node's read API and indirectly against its ability to keep up with ingesting new gossip-derived transaction records.

### Likelihood Explanation

The endpoint is public, unauthenticated, and requires no special knowledge beyond the documented API. The exploit is a single HTTP GET with `limit=100` and no filters. It is trivially repeatable and scriptable. Any attacker with network access to the mirror node REST port can execute it. No credentials, tokens, or privileged access are required.

### Recommendation

1. **Replace the correlated scalar subquery with a pre-aggregated lateral join or a single aggregation CTE keyed by `account_id`**, so the `token_account` table is scanned once and results are joined — not re-scanned per row.
2. **Add rate limiting** (e.g., per-IP request rate) on the `/api/v1/accounts` endpoint.
3. **Ensure an index exists on `token_account(account_id)` where `associated = true`** so that even if the correlated subquery pattern is retained, each execution uses an index seek rather than a sequential scan.
4. Consider lowering `tokenBalanceResponseLimit.multipleAccounts` or requiring an explicit `account.id` filter when `limit` is large.

### Proof of Concept

**Preconditions:** Mirror node REST API accessible at `http://mirror-node:5551`. No credentials needed.

**Step 1 — Single amplified request:**
```
GET /api/v1/accounts?limit=100
```
Causes PostgreSQL to execute the `latest_token_balance` correlated subquery 100 times, each scanning the full `token_account` table.

**Step 2 — Flood to exhaust DB pool:**
```bash
# Send 50 concurrent requests in a loop
for i in $(seq 1 50); do
  curl -s "http://mirror-node:5551/api/v1/accounts?limit=100" &
done
wait
```
Each of the 50 concurrent requests holds a DB connection for up to the statement timeout (10 s), executing 100 × 50 = 5,000 correlated subquery scans simultaneously. This saturates the DB connection pool and CPU, causing all other queries (transactions, balances, importer writes) to queue or time out.

**Observable result:** Subsequent requests to `/api/v1/transactions` or `/api/v1/accounts/{id}` return 503 or time out; DB CPU reaches 100%; mirror node falls behind on ingesting new gossip transactions.

### Citations

**File:** rest/accounts.js (L183-195)
```javascript
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
```

**File:** rest/accounts.js (L345-345)
```javascript
  const tokenBalanceQuery = {query: 'account_id = e.id', params: [], limit: tokenBalanceResponseLimit.multipleAccounts};
```

**File:** rest/__tests__/config.test.js (L325-325)
```javascript
    expect(func()).toEqual({default: 25, max: 100, tokenBalance: {multipleAccounts: 50, singleAccount: 1000}});
```

**File:** rest/utils.js (L544-553)
```javascript
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```

**File:** docs/configuration.md (L610-610)
```markdown
| `hiero.mirror.rest.response.limit.tokenBalance.multipleAccounts`         | 50                      | The maximum number of token balances per account for endpoints which return such info for multiple accounts                                                                                   |
```
