### Title
Unauthenticated 1-Nanosecond Timestamp Range Triggers Guaranteed-Empty DB Query in `getBalances()`, Enabling Connection Pool Exhaustion

### Summary
Any unauthenticated caller can supply `timestamp=gt:<X>&timestamp=lt:<X+2>` to the `/api/v1/balances` endpoint. After `getOptimizedTimestampRange()` converts `gt` → `gte` (+1 ns) and `lt` → `lte` (-1 ns), the effective range collapses to `[X+1, X+1]` — a single nanosecond. This passes the only guard (`lowerBound > upperBound`), so `getAccountBalanceTimestampRange()` unconditionally fires a PostgreSQL query that virtually never matches a real balance-snapshot timestamp, wasting one connection-pool slot per request. Repeated at scale this exhausts the pool and degrades or denies service to legitimate users.

### Finding Description

**Full call chain:**

`getBalances()` → `getTsQuery()` → `getAccountBalanceTimestampRange()` → `getOptimizedTimestampRange()`

**Step 1 — parsing (no range validation).**
`parseTimestampQueryParam` (rest/utils.js:694-700) builds a raw SQL fragment and a params array from each individual timestamp filter. It calls `parseTimestampParam` per value (format check only) and never invokes `parseTimestampFilters` (which has the `difference <= 0n` guard at utils.js:1661).

**Step 2 — `getOptimizedTimestampRange` (balances.js:229-276).**
For `timestamp=gt:<X>&timestamp=lt:<X+2>`:
- `gt:<X>` branch (line 251-254): `lowerBound = X + 1n`
- `lt:<X+2>` branch (line 244-247): `upperBound = (X+2) - 1n = X + 1n`

The only guard is:
```js
if (lowerBound > upperBound) {   // line 260
  return {};
}
```
`X+1 > X+1` is **false**, so the function proceeds and returns `{lowerBound: X+1, upperBound: X+1, neParams: []}`.

**Step 3 — `getAccountBalanceTimestampRange` (balances.js:167-197).**
`lowerBound !== undefined`, so the function builds and executes:
```sql
SELECT consensus_timestamp
FROM account_balance
WHERE account_id = $1          -- treasury account
  AND consensus_timestamp >= $2  -- X+1
  AND consensus_timestamp <= $3  -- X+1
ORDER BY consensus_timestamp DESC
LIMIT 1
```
Balance snapshots are taken at most every few minutes; the probability of one landing on an arbitrary single nanosecond is effectively zero. The query returns 0 rows, `getAccountBalanceTimestampRange` returns `{}`, `getTsQuery` returns `{}`, and `getBalances` exits early at line 115-117 — but only **after** the DB round-trip has already consumed a connection slot.

**Why existing checks fail:**
- `filterValidityChecks` for `TIMESTAMP` (utils.js:362-363) only calls `isValidTimestampParam(val)` — a regex format check on each individual value; no cross-value range check.
- `isEmptyRange` (utils.js:901-946) checks `upper < lower` (strict), so equal bounds return `false`; moreover it is never called in the balances validation path.
- `parseTimestampFilters` (utils.js:1583-1681), which does check `difference <= 0n`, is **not** used by `getBalances`; the balances endpoint uses the older `parseTimestampQueryParam` path.
- No application-level rate limiting exists in the REST API JavaScript layer (confirmed: zero matches for `rateLimit` in `rest/**/*.js`).

### Impact Explanation

Each crafted request causes one synchronous PostgreSQL query to execute and hold a connection from the pool (`max: config.db.pool.maxConnections`, configured in `rest/dbpool.js:14`). With enough concurrent requests the pool is saturated; subsequent legitimate requests queue or time out (`connectionTimeoutMillis`, dbpool.js:13). Because the query is fast (indexed PK lookup), the attacker needs high concurrency rather than long-running queries, but this is trivially achievable with async HTTP clients. The result is degraded or complete denial of the `/api/v1/balances` endpoint for all users — a griefing impact with no economic cost to the attacker.

### Likelihood Explanation

The endpoint is public and requires no credentials. The payload is a standard HTTP GET with two query parameters. Any HTTP client capable of sending concurrent requests (curl, ab, wrk, Python asyncio) can execute this. The attacker needs no knowledge of internal state; any value of `X` works. The attack is repeatable indefinitely and stateless, making it trivially scriptable.

### Recommendation

Apply one or more of the following in `getOptimizedTimestampRange` or `getAccountBalanceTimestampRange`:

1. **Reject degenerate ranges before querying.** After computing `lowerBound`/`upperBound`, add a minimum-width guard:
   ```js
   const MIN_RANGE_NS = 1_000_000_000n; // e.g. 1 second
   if (upperBound - lowerBound < MIN_RANGE_NS) {
     return {};
   }
   ```
   Returning `{}` here causes `getBalances` to return an empty response without touching the DB.

2. **Route through `parseTimestampFilters`.** Replace the custom `getOptimizedTimestampRange` parsing with a call to `parseTimestampFilters` (utils.js:1583), which already enforces `difference > 0n` and a configurable `maxTimestampRangeNs`.

3. **Add application-level rate limiting** to the REST API (analogous to the `ThrottleConfiguration` already present in the `web3` service) as a defence-in-depth measure.

### Proof of Concept

```bash
# Pick any timestamp X (e.g. current time in nanoseconds)
X=1700000000000000000

# Single request — triggers a guaranteed-empty DB query
curl "https://<mirror-node>/api/v1/balances?timestamp=gt:${X}.000000000&timestamp=lt:$((X+2)).000000000"
# Returns: {"timestamp":null,"balances":[],"links":{"next":null}}

# Flood to exhaust connection pool (adjust -c to pool maxConnections)
ab -n 100000 -c 200 \
  "https://<mirror-node>/api/v1/balances?timestamp=gt:${X}.000000000&timestamp=lt:$((X+2)).000000000"

# Observe: legitimate /api/v1/balances requests begin timing out or returning 503
```