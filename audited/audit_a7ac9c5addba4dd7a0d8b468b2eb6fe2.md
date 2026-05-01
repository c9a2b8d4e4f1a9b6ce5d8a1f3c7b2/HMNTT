### Title
Unbounded Timestamp Range in `getOneAccount()` Enables Parallel DB Query Exhaustion DoS

### Summary
`getOneAccount()` in `rest/accounts.js` calls `parseTimestampFilters` with `validateRange=false` and `allowOpenRange=true`, bypassing the configured `maxTimestampRange` (7d) check entirely. This allows an unauthenticated attacker to supply an unbounded or arbitrarily large timestamp range, which is then passed simultaneously to both an expensive `entity UNION ALL entity_history` query and `doGetTransactions()`, both executing in parallel via `Promise.all`. Flooding the endpoint with such requests exhausts the finite DB connection pool, causing sustained denial of service for the REST API tier.

### Finding Description

**Root cause — `validateRange=false` in `getOneAccount()`:** [1](#0-0) 

```js
const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
```

The sixth argument is `validateRange=false`. Inside `parseTimestampFilters`, the only place `maxTimestampRangeNs` (default 7 days) is enforced is: [2](#0-1) 

Because `validateRange=false`, this block is skipped entirely. Combined with `allowOpenRange=true` (fourth argument), a single-sided filter like `timestamp=gte:0` is accepted with no upper bound.

**Parallel expensive queries — `Promise.all`:** [3](#0-2) 

Both `entityPromise` and `transactionsPromise` are launched concurrently. When `timestampFilters.length > 0`, the entity query becomes a full `UNION ALL` between `entity` and `entity_history`: [4](#0-3) 

The transaction query path (`doGetTransactions` → `getTransactionTimestamps`) only caps the range when `config.query.bindTimestampRange=true`, which defaults to `false`: [5](#0-4) 

With `bindTimestampRange=false` (default), the unbounded range is passed directly to the SQL query scanning `transaction`, `crypto_transfer`, `token_transfer`, and `entity_transaction` tables via a multi-table FULL OUTER JOIN: [6](#0-5) 

**DB pool is finite and shared:** [7](#0-6) 

`max: config.db.pool.maxConnections` — a single global pool. Each `getOneAccount` request with a timestamp filter consumes 2 pool connections simultaneously (entity + transactions). With a default pool of ~10 connections, 5 concurrent malicious requests saturate the pool. Subsequent legitimate requests receive connection timeout errors.

### Impact Explanation
The REST API's DB connection pool is exhausted, causing all subsequent API requests (accounts, transactions, balances, etc.) to fail with connection timeout errors. This degrades or completely halts the mirror node REST API tier. The `statementTimeout` provides partial mitigation (queries are killed after N ms), but during that window all pool slots are held, and the attack is trivially repeatable at a rate that keeps the pool permanently saturated. No authentication is required.

### Likelihood Explanation
Any unauthenticated user can issue `GET /api/v1/accounts/0.0.2?timestamp=gte:0`. The endpoint is publicly documented and accessible. The attack requires no special knowledge beyond the API spec. A single attacker with a modest request rate (e.g., 5–10 concurrent requests/second) can sustain pool exhaustion indefinitely. No CAPTCHA, rate limiting, or IP throttling exists in the REST JS layer (unlike the web3 Java component which has `ThrottleManagerImpl`). [8](#0-7) 

### Recommendation
1. **Remove `validateRange=false`** from the `parseTimestampFilters` call in `getOneAccount()`. The entity history lookup does not require bypassing range validation; the `allowOpenRange=true` flag already handles the case where only one bound is provided.
2. **Enforce `maxTransactionsTimestampRange`** unconditionally in `doGetTransactions` regardless of `bindTimestampRange` config, or cap the range before passing it to `getTransactionTimestamps`.
3. **Add per-IP or global request-rate limiting** to the REST JS API (similar to the `ThrottleManagerImpl` in the web3 Java component).
4. **Reduce `maxConnections`** per REST node and add a connection-acquisition timeout that returns HTTP 503 instead of hanging.

### Proof of Concept

**Preconditions:** Mirror node REST API is publicly accessible; at least one valid account ID exists (e.g., `0.0.2`).

**Trigger (single expensive request):**
```
GET /api/v1/accounts/0.0.2?timestamp=gte:0
```
This bypasses `validateRange`, creates an open-ended range from timestamp 0, and fires two parallel DB queries:
1. `SELECT ... FROM entity UNION ALL SELECT ... FROM entity_history WHERE timestamp_range && [0,)` — full scan of both tables.
2. Multi-table FULL OUTER JOIN on `transaction`, `crypto_transfer`, `token_transfer` with `consensus_timestamp >= 0` — full table scan.

**Sustained DoS (pool exhaustion):**
```bash
# Send 10 concurrent requests in a loop
while true; do
  for i in $(seq 1 10); do
    curl -s "http://<mirror-node>/api/v1/accounts/0.0.2?timestamp=gte:0" &
  done
  wait
done
```

**Result:** DB connection pool is saturated. All other REST API endpoints return connection timeout errors. The attack is sustained as long as the loop runs, with no authentication required.

### Citations

**File:** rest/accounts.js (L210-219)
```javascript
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

**File:** rest/accounts.js (L413-413)
```javascript
  const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
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

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```

**File:** rest/transactions.js (L464-468)
```javascript
  if (timestampRange.eqValues.length === 0) {
    const {range, next} = await bindTimestampRange(timestampRange.range, order);
    timestampRange.range = range;
    nextTimestamp = next;
  }
```

**File:** rest/transactions.js (L595-604)
```javascript
    return `
        select coalesce(t.consensus_timestamp, ctl.consensus_timestamp, ttl.consensus_timestamp) as consensus_timestamp,
               coalesce(t.payer_account_id, ctl.payer_account_id, ttl.payer_account_id)          as payer_account_id
        from (${transactionOnlyQuery}) as t
                 full outer join (${cryptoTransferQuery}) as ctl
                                 on t.consensus_timestamp = ctl.consensus_timestamp
                 full outer join (${tokenTransferQuery}) as ttl
                                 on coalesce(t.consensus_timestamp, ctl.consensus_timestamp) = ttl.consensus_timestamp
        order by consensus_timestamp ${order}
            ${limitQuery}`;
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
