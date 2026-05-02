### Title
Unauthenticated Connection Pool Exhaustion via Concurrent Timestamp-Filtered Transaction Queries

### Summary
The `/api/v1/transactions` endpoint in `rest/transactions.js` has no application-level rate limiting, and each request consumes multiple database connections from a pool defaulting to only 10 connections. An unprivileged attacker can exhaust the connection pool by sending a small number of concurrent requests with valid timestamp filters and `limit=1`, causing all subsequent REST API requests to fail with connection timeout errors.

### Finding Description

**Code path:**

`getTransactions` (line 671) → `doGetTransactions` (line 695) → `getTransactionTimestamps` (line 451) → `pool.queryQuietly` (line 483) → `getTransactionsDetails` (line 616) → `pool.queryQuietly` (line 662) → `createStakingRewardTransferList` (line 253) → `getStakingRewardTransferList` (line 265) → `pool.queryQuietly` (line 280).

Each single HTTP request to `/api/v1/transactions` can consume **2–3 database connections** sequentially from the shared pool.

**Root cause — pool size:** [1](#0-0) 

The pool is initialized with `max: config.db.pool.maxConnections`, which defaults to **10 connections**: [2](#0-1) 

**Root cause — no rate limiting:**

The REST API server registers the transactions route with no rate-limiting middleware: [3](#0-2) 

A `grep` across all `rest/**/*.js` files for `rateLimit`, `rateLimiter`, or `throttle` returns only one hit in a test utility file — confirming zero application-level rate limiting. The Traefik middleware that could provide rate limiting is **disabled by default** (`global.middleware: false`): [4](#0-3) 

**Root cause — multiple queries per request:**

`getTransactionTimestamps` always fires one DB query: [5](#0-4) 

`doGetTransactions` then fires a second query via `getTransactionsDetails`: [6](#0-5) 

And a third query is fired if any transaction involves the staking reward account: [7](#0-6) 

**Why the `timestamp.eq` + `limit=1` specific scenario partially works:**

A single `timestamp.eq` value passes the guard at line 452 (`eqValues.length > 1` is false), skips `bindTimestampRange` (line 464, since `eqValues.length !== 0`), and proceeds directly to the DB query. With `limit=1`, the response returns one row and generates a `next` pagination link. However, strict timestamp validation (`strictTimestampParam: true` by default) prevents combining `eq` with range operators on the follow-up paginated request. The practical attack therefore uses **concurrent** requests with valid range filters (`timestamp.gte=X&timestamp.lte=Y&limit=1`) rather than chained `eq` pagination — each request still exhausts 2–3 connections. [8](#0-7) 

### Impact Explanation

With a default pool of 10 connections and 2–3 connections consumed per request, only **4–5 concurrent requests** are needed to exhaust the pool. Once exhausted, all subsequent requests wait up to `connectionTimeoutMillis` (default 20 seconds) before failing. This causes a complete denial of service of the mirror node REST API for all legitimate users. The `statement_timeout` (20 seconds) limits individual query duration but does not prevent pool exhaustion — an attacker simply maintains a steady stream of concurrent requests.

### Likelihood Explanation

The attack requires no authentication, no special knowledge of the system, and no privileged access. Any HTTP client capable of sending concurrent requests (e.g., `curl`, `ab`, `wrk`, a simple Python script) can trigger this. The attacker needs only to know a valid timestamp range (publicly observable from any prior API response). The attack is repeatable indefinitely and requires minimal resources on the attacker's side.

### Recommendation

1. **Add application-level rate limiting** per source IP in the REST API middleware (e.g., `express-rate-limit`), applied before route handlers.
2. **Increase the default pool size** or configure it relative to expected concurrency; 10 is far too small for a public API.
3. **Enable Traefik middleware by default** for the REST chart, including `inFlightReq` and `rateLimit` entries similar to those already defined for the Rosetta chart.
4. **Add a per-request connection acquisition timeout** that returns HTTP 503 immediately when the pool is exhausted rather than queuing requests for 20 seconds.

### Proof of Concept

```bash
# Step 1: Obtain a valid timestamp range from any prior response
RANGE_START="1638921702.000000000"
RANGE_END="1638921762.000000000"

# Step 2: Fire 10 concurrent requests (enough to exhaust the 10-connection pool)
for i in $(seq 1 10); do
  curl -s "https://<mirror-node>/api/v1/transactions?timestamp=gte:${RANGE_START}&timestamp=lte:${RANGE_END}&limit=1" &
done
wait

# Step 3: Observe that subsequent legitimate requests time out or return 500
curl -v "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: connection timeout or pool exhaustion error after ~20 seconds
```

Maintaining this loop continuously (e.g., with `wrk -t4 -c10 -d60s`) will sustain the DoS for the duration of the attack.

### Citations

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

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
```

**File:** rest/server.js (L131-133)
```javascript
// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);
```

**File:** charts/hedera-mirror-rest/values.yaml (L89-89)
```yaml
  middleware: false
```

**File:** rest/transactions.js (L265-281)
```javascript
const getStakingRewardTransferList = async (stakingRewardTimestamps) => {
  if (stakingRewardTimestamps.length === 0) {
    return [];
  }

  const positions = range(1, stakingRewardTimestamps.length + 1).map((position) => `$${position}`);
  const query = `
      select ${StakingRewardTransfer.CONSENSUS_TIMESTAMP},
             json_agg(json_build_object(
                     'account', ${StakingRewardTransfer.ACCOUNT_ID},
                     '${StakingRewardTransfer.AMOUNT}', ${StakingRewardTransfer.AMOUNT})) as staking_reward_transfers
      from ${StakingRewardTransfer.tableName}
      where ${StakingRewardTransfer.CONSENSUS_TIMESTAMP} in (${positions})
      group by ${StakingRewardTransfer.CONSENSUS_TIMESTAMP}`;

  const {rows} = await pool.queryQuietly(query, stakingRewardTimestamps);
  return rows;
```

**File:** rest/transactions.js (L451-486)
```javascript
const getTransactionTimestamps = async (filters, timestampRange) => {
  if (timestampRange.eqValues.length > 1 || timestampRange.range?.isEmpty()) {
    return {rows: []};
  }

  const result = extractSqlFromTransactionsRequest(filters);
  if (result === null) {
    return {rows: []};
  }
  const {accountQuery, creditDebitQuery, limit, limitQuery, order, resultTypeQuery, transactionTypeQuery, params} =
    result;

  let nextTimestamp;
  if (timestampRange.eqValues.length === 0) {
    const {range, next} = await bindTimestampRange(timestampRange.range, order);
    timestampRange.range = range;
    nextTimestamp = next;
  }

  let [timestampQuery, timestampParams] = utils.buildTimestampQuery('t.consensus_timestamp', timestampRange);
  timestampQuery = utils.convertMySqlStyleQueryToPostgres(timestampQuery, params.length + 1);
  params.push(...timestampParams);

  const query = getTransactionTimestampsQuery(
    accountQuery,
    timestampQuery,
    resultTypeQuery,
    limitQuery,
    creditDebitQuery,
    transactionTypeQuery,
    order
  );
  const {rows} = await pool.queryQuietly(query, params);

  return {limit, order, nextTimestamp, rows};
};
```

**File:** rest/transactions.js (L703-705)
```javascript
  const loader = (keys) => getTransactionsDetails(keys, order).then((result) => formatTransactionRows(result.rows));

  const transactions = await cache.get(payerAndTimestamps, loader, keyMapper);
```
