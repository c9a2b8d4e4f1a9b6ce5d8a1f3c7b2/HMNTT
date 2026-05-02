### Title
Unbounded Concurrent Correlated Subquery Amplification in `getBalancesQuery()` Enables Mirror Node DoS and Ingestion Halt

### Summary
When a `timestamp` filter is supplied to `GET /api/v1/balances`, `getBalancesQuery()` builds a single SQL statement containing a correlated scalar subquery (`getTokenBalanceSubQuery()`) in the SELECT list that references `ab.account_id` from the outer row. PostgreSQL evaluates this subquery once per row emitted by the outer `SELECT DISTINCT ON (account_id)` scan, producing up to `limit` (max 100) expensive `token_balance` range scans per HTTP request. Because the REST API carries no rate-limiting middleware, an unauthenticated attacker can flood the endpoint with concurrent requests, saturating the shared PostgreSQL connection pool and I/O, which starves the importer (ingestion pipeline) that writes to the same database.

### Finding Description

**Exact code path:**

`rest/balances.js` lines 199–218 (`getBalancesQuery`):
```js
const tokenBalanceSubQuery = getTokenBalanceSubQuery(order, tsQueryResult.query);
// ...
const sqlQuery = `
    select distinct on (account_id)
      ab.account_id,
      ab.balance,
      ?::bigint as consensus_timestamp,
      (${tokenBalanceSubQuery}) as token_balances   // ← correlated subquery in SELECT list
    from account_balance ab
    ${whereClause}
    order by ab.account_id ${order}, ab.consensus_timestamp desc
    ${limitQuery}`;
```

`rest/balances.js` lines 294–306 (`getTokenBalanceSubQuery`):
```js
const getTokenBalanceSubQuery = (order, consensusTsQuery) => {
  consensusTsQuery = consensusTsQuery.replaceAll('ab.', 'tb.');
  return `
    select json_agg(...)
    from (
      select distinct on (token_id) token_id, balance
      from token_balance tb
      where tb.account_id = ab.account_id   // ← correlated reference
        and ${consensusTsQuery}
      order by token_id ${order}, consensus_timestamp desc
      limit ${tokenBalanceLimit.multipleAccounts}   // 50 by default
    ) as account_token_balance`;
};
```

**Root cause:** The subquery is a correlated scalar subquery in the projection list. PostgreSQL evaluates it once per output row of the outer `DISTINCT ON` query. With `limit=100` (the configured maximum), this means up to 100 independent `token_balance` range scans — each doing `DISTINCT ON (token_id)` over a timestamp window — execute serially inside a single database query.

**Failed assumption:** The designers assumed the `LIMIT` cap (max 100) makes the per-request cost acceptable. This is true for a single request in isolation, but the REST server (`rest/server.js` lines 100–106) registers the `/api/v1/balances` route with **no rate-limiting middleware** between the route registration and the handler. The only throttle infrastructure in the codebase (`web3/src/main/java/.../ThrottleConfiguration.java`) applies exclusively to the `web3` contract-call module, not to the REST API.

**Exploit flow:**
1. Attacker identifies a valid recent timestamp (trivially obtained from any prior API response or block explorer).
2. Attacker sends `N` concurrent requests: `GET /api/v1/balances?timestamp=lte:<valid_ts>&limit=100`.
3. Each request causes the DB to execute one outer `account_balance` range scan plus up to 100 correlated `token_balance` `DISTINCT ON` subqueries.
4. With `N=50` concurrent connections, the DB is executing up to 5,000 correlated subqueries simultaneously.
5. The `token_balance` table on a production mirror node contains hundreds of millions of rows (15-minute snapshots × all accounts × all tokens). Each correlated subquery must scan a timestamp-partitioned slice of this table.
6. PostgreSQL connection pool and I/O are saturated; the importer (which uses the same pool) cannot acquire connections to write new ingested data.

**Why existing checks fail:**
- `limit` cap (max 100): bounds per-request amplification but does not prevent concurrent amplification.
- Timestamp range optimization (`getOptimizedTimestampRange`, lines 229–276): narrows the scan to at most two monthly partitions, but two months of `token_balance` data on mainnet is still hundreds of millions of rows.
- No `statement_timeout` or `lock_timeout` is set on the query path through `pool.queryQuietly` for this endpoint.
- No IP-based or global rate limiter exists in `rest/server.js`.

### Impact Explanation
The mirror node's REST API and importer share the same PostgreSQL instance. Saturating the DB connection pool and disk I/O prevents the importer from writing newly ingested transactions, effectively halting the mirror node's view of the network from advancing. This does **not** affect Hedera network consensus (the mirror node is a read-only replica), but it does halt mirror node ingestion and makes the REST API unavailable, breaking all downstream applications (wallets, explorers, dApps) that depend on the mirror node for balance and transaction data.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a single valid timestamp value (publicly available from any prior API response). The endpoint is publicly accessible on all production mirror node deployments. The attack is trivially scriptable with `curl` or any HTTP load tool. It is repeatable indefinitely until rate limiting or network-level controls are added. The `token_balance` table size on mainnet makes each correlated subquery genuinely expensive, amplifying the effect.

### Recommendation
1. **Add rate limiting to the REST API**: Apply a per-IP and global request rate limiter (e.g., `express-rate-limit`) in `rest/server.js` before the balances route, mirroring the throttle pattern used in the `web3` module.
2. **Set a `statement_timeout`** on the PostgreSQL connection or per-query in `pool.queryQuietly` for the balances endpoint to bound maximum query duration.
3. **Eliminate the correlated subquery**: Rewrite `getBalancesQuery()` to use a lateral join or a single `token_balance` range scan with a `GROUP BY account_id` instead of a per-row correlated subquery, so the `token_balance` table is scanned once rather than N times.
4. **Require authentication or stricter parameter validation** for the timestamp-filtered path, which is the more expensive code branch.

### Proof of Concept
```bash
# Step 1: Obtain a valid recent timestamp from any public mirror node response
TS=$(curl -s "https://<mirror-node>/api/v1/transactions?limit=1" \
  | jq -r '.transactions[0].consensus_timestamp')

# Step 2: Fire 100 concurrent requests with max limit
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/balances?timestamp=lte:${TS}&limit=100" \
    -o /dev/null &
done
wait

# Repeat in a tight loop. Each iteration issues 100 concurrent requests,
# each triggering up to 100 correlated token_balance subqueries (10,000 total).
# Monitor pg_stat_activity on the DB to observe connection pool exhaustion
# and importer write latency increasing until ingestion stalls.
```