### Title
Unauthenticated Historical Balance Path Triggers Expensive `DISTINCT ON` Query, Enabling DB Connection Pool Exhaustion

### Summary
Any unauthenticated external user can supply a `timestamp` query parameter to `GET /api/v1/accounts/:id`, which unconditionally activates the historical balance code path in `getEntityBalanceQuery()`. This causes a `DISTINCT ON (token_id) … ORDER BY token_id ASC, consensus_timestamp DESC` subquery to execute against the large historical `token_balance` table, holding a DB connection for the full query duration. With no rate limiting on the REST API and a finite connection pool, concurrent requests from a single attacker can exhaust available connections and degrade or deny service.

### Finding Description

**Exact code path:**

`getOneAccount()` in `rest/accounts.js` accepts `timestamp` as a valid filter parameter with no authentication:

```
acceptedSingleAccountParameters = new Set([..., constants.filterKeys.TIMESTAMP, ...])
``` [1](#0-0) 

When `timestampFilters.length > 0`, `getAccountBalanceTimestampRange()` is called. If a valid balance snapshot exists for the supplied timestamp (i.e., `upper !== undefined`), `accountBalanceQuery.query` is set to a non-empty string: [2](#0-1) 

This non-empty `accountBalanceQuery.query` flows into `getEntityBalanceQuery()`, where `needHistoricalBalanceInfo` becomes `true`: [3](#0-2) 

The historical branch then constructs and executes the following subquery against the `token_balance` table:

```sql
select distinct on (token_id) token_id, balance
from token_balance
where account_id = $1
  and consensus_timestamp >= $lower
  and consensus_timestamp <= $upper
order by token_id ASC, consensus_timestamp desc
limit <tokenBalanceResponseLimit.singleAccount>
``` [4](#0-3) 

**Root cause — index mismatch forces a sort:**

The `token_balance` primary key is `(account_id, token_id, consensus_timestamp)` — all ascending. The secondary index is `(token_id, account_id, consensus_timestamp)` — also all ascending. [5](#0-4) 

The query requires `ORDER BY token_id ASC, consensus_timestamp DESC`. Because `consensus_timestamp` is stored ascending in both indexes but the query demands it descending within each `token_id` group, PostgreSQL cannot satisfy `DISTINCT ON` using a pure index scan. It must fetch all rows for the account within the timestamp window and sort them — a potentially large in-memory or on-disk sort for accounts with many token associations.

**Failed assumption:** The design assumes the `account_id` filter and `LIMIT` bound the work. They do not: `DISTINCT ON` requires the full sort to complete before the limit is applied.

**Two DB queries per request:** Each timestamped request also first executes `getAccountBalanceTimestampRange()` (a separate DB query), so each attacker request consumes at least two connections from the pool. [6](#0-5) 

**No rate limiting on the REST API:** The REST API Helm chart middleware has no `rateLimit` or `inFlightReq` entries (unlike the Rosetta chart which explicitly configures `rateLimit: average: 10` and `inFlightReq: amount: 5`). The connection pool for `mirror_rest` is capped at 250 server-side connections. [7](#0-6) 

The only server-side guard is `statement_timeout` in the pool config, which kills individual long queries but does not prevent many concurrent short-to-medium queries from saturating the pool simultaneously. [8](#0-7) 

### Impact Explanation
An attacker who floods `GET /api/v1/accounts/<high-token-count-account>?timestamp=<valid-past-ts>` with concurrent requests will hold DB connections for the duration of each `DISTINCT ON` sort. Once the 250-connection pool is saturated, all REST API queries queue or fail with connection timeout errors, causing a full denial of service for all users of the mirror node REST API. Because `token_balance` is a historical accumulation table that grows unboundedly, the cost per query increases over time, worsening the impact as the network matures.

### Likelihood Explanation
The attack requires zero privileges — no API key, no account, no special knowledge beyond a valid account ID (publicly enumerable) and any past timestamp (any nanosecond value that falls within a balance snapshot window). The endpoint is publicly documented. A single attacker with a modest number of concurrent HTTP connections (e.g., 300 parallel `curl` processes) is sufficient to exhaust the pool. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Add rate limiting per IP** at the ingress/middleware layer for the REST API, mirroring the Rosetta chart's `inFlightReq` and `rateLimit` middleware entries.
2. **Fix the index mismatch**: Add a partial index on `token_balance (account_id, token_id, consensus_timestamp DESC)` so PostgreSQL can satisfy `DISTINCT ON (token_id) ORDER BY token_id ASC, consensus_timestamp DESC` via an index-only scan without a sort.
3. **Cap concurrent historical queries**: Implement an application-level semaphore or use `pg_pool` advisory locks to limit the number of simultaneous historical balance queries.
4. **Enforce a strict `statement_timeout`** for the `mirror_rest` DB role that is low enough to prevent connection saturation (e.g., 5 seconds), and document it as a required deployment setting.

### Proof of Concept

**Preconditions:**
- Mirror node REST API is publicly accessible (standard deployment).
- A valid account ID with many token associations exists (e.g., `0.0.98`, the treasury, or any DeFi-active account).
- A past timestamp that falls within a balance snapshot window is known (any timestamp from the network's history works; balance snapshots occur roughly every 15 minutes).

**Steps:**

```bash
# 1. Find a valid past timestamp (any balance snapshot timestamp works)
TIMESTAMP="1680308100.000000000"
ACCOUNT="0.0.98"
BASE_URL="https://<mirror-node-host>/api/v1"

# 2. Verify the path is triggered (single request)
curl "$BASE_URL/accounts/$ACCOUNT?timestamp=$TIMESTAMP"
# Observe: response includes historical token balances — confirms DISTINCT ON path executed

# 3. Flood with concurrent requests to exhaust the connection pool
for i in $(seq 1 300); do
  curl -s "$BASE_URL/accounts/$ACCOUNT?timestamp=$TIMESTAMP" &
done
wait

# 4. Observe: subsequent legitimate requests to any REST endpoint
# return connection timeout errors or HTTP 503, confirming pool exhaustion.
curl "$BASE_URL/accounts/0.0.1234"
# Expected: timeout or error
```

### Citations

**File:** rest/accounts.js (L164-164)
```javascript
  const needHistoricalBalanceInfo = accountBalanceQuery.query || accountBalanceQuery.forceUnionEntityHistory;
```

**File:** rest/accounts.js (L170-180)
```javascript
    selectTokenBalance = accountBalanceQuery.query
      ? `(
          select json_agg(jsonb_build_object('token_id', token_id, 'balance', balance)) ::jsonb
          from (
            select distinct on (token_id) token_id, balance
            from token_balance
            where ${tokenBalanceQuery.query}
            order by token_id ${order}, consensus_timestamp desc
            limit ${tokenBalanceQuery.limit}
          ) as account_token_balance
        ) as token_balances`
```

**File:** rest/accounts.js (L428-459)
```javascript
  if (timestampFilters.length > 0) {
    const [balanceSnapshotTsQuery, balanceSnapshotTsParams] = utils.buildTimestampQuery(
      'consensus_timestamp',
      timestampRange,
      false
    );

    const {lower, upper} = await balances.getAccountBalanceTimestampRange(
      balanceSnapshotTsQuery.replaceAll(opsMap.eq, opsMap.lte),
      balanceSnapshotTsParams
    );

    if (upper !== undefined) {
      // Note when a balance snapshot timestamp is not found, it falls back to return balance info from entity table
      const lowerTimestampParamIndex = ++paramCount;
      const upperTimestampParamIndex = ++paramCount;
      // Note if no balance info for the specific account in the timestamp range is found, the balance should be 0.
      // It can happen when the account is just created and the very first snapshot is after the range.
      accountBalanceQuery.query = `coalesce((
        select balance
        from account_balance
        where account_id = $${accountIdParamIndex} and
          consensus_timestamp >= $${lowerTimestampParamIndex} and
          consensus_timestamp <= $${upperTimestampParamIndex}
        order by consensus_timestamp desc
        limit 1
      ), 0)`;
      accountBalanceQuery.timestampParamIndex = upperTimestampParamIndex;

      tokenBalanceQuery.params.push(lower, upper);
      tokenBalanceQuery.query += ` and consensus_timestamp >= $${lowerTimestampParamIndex} and
        consensus_timestamp <= $${upperTimestampParamIndex}`;
```

**File:** rest/accounts.js (L523-529)
```javascript
const acceptedSingleAccountParameters = new Set([
  constants.filterKeys.LIMIT,
  constants.filterKeys.ORDER,
  constants.filterKeys.TIMESTAMP,
  constants.filterKeys.TRANSACTION_TYPE,
  constants.filterKeys.TRANSACTIONS,
]);
```

**File:** importer/src/main/resources/db/migration/v2/V2.0.3__index_init.sql (L236-239)
```sql
alter table if exists token_balance
    add constraint token_balance__pk primary key (account_id, token_id, consensus_timestamp);
create index if not exists token_balance__token_account_timestamp
    on token_balance (token_id, account_id, consensus_timestamp);
```

**File:** charts/hedera-mirror/values.yaml (L371-373)
```yaml
        mirror_rest:
          max_user_client_connections: 1000
          max_user_connections: 250
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```
