### Title
Unauthenticated Unbounded Timestamp Range Scan on `/api/v1/transactions` Due to Disabled Range Validation

### Summary
`getTransactions()` in `rest/transactions.js` calls `parseTimestampFilters` with `validateRange=false`, entirely bypassing the `maxTimestampRangeNs` (7-day) guard. The secondary protection, `bindTimestampRange`, is gated behind a config flag that defaults to `false`. In the default deployment, any unauthenticated user can supply an arbitrarily wide (or fully open) timestamp range, causing `getTransactionTimestamps()` to issue a full-table scan against the `transaction` table with no width limit.

### Finding Description

**Exact code path:**

`getTransactions()` at `rest/transactions.js:674` calls:
```js
utils.parseTimestampFilters(timestampFilters, false, true, true, false, false)
```
The sixth argument maps to `validateRange = false`. [1](#0-0) 

Inside `parseTimestampFilters` (`rest/utils.js:1657–1666`), the only range-width check is wrapped in `if (validateRange)`. With `validateRange=false`, the block is skipped entirely — `maxTimestampRangeNs` (default 7 days) is never consulted. [2](#0-1) 

The third argument `allowOpenRange=true` additionally allows a request with only one bound (e.g., `timestamp=gte:0`), which would produce a range with no upper bound. [3](#0-2) 

**Secondary protection — `bindTimestampRange` — is off by default:**

In `getTransactionTimestamps()`, `bindTimestampRange` is called to enforce `maxTransactionsTimestampRangeNs` (default 60 days): [4](#0-3) 

But `bindTimestampRange` immediately returns the range unchanged when `queryConfig.bindTimestampRange` is falsy: [5](#0-4) 

The documented default for this flag is `false`: [6](#0-5) 

**Result:** The user-supplied range — potentially spanning the entire transaction history — is passed verbatim to `pool.queryQuietly(query, params)` at line 483, executing a full-table scan on the `transaction` table. [7](#0-6) 

### Impact Explanation

The `transaction` table in a production Hedera mirror node accumulates billions of rows. A full-table scan (or a scan spanning years of data) consumes significant DB I/O, CPU, and memory. The DB connection pool is capped at 10 connections by default (`db.pool.maxConnections = 10`). A small number of concurrent requests (each holding a connection for up to the 20-second `statementTimeout`) can exhaust the pool, causing all other API endpoints to queue or fail. This directly degrades availability across the mirror node REST API, consistent with the ≥30% node processing degradation threshold described in the finding scope. [8](#0-7) 

### Likelihood Explanation

No authentication, API key, or rate-limiting is required. The `/api/v1/transactions` endpoint is publicly documented and accessible. The exploit requires only a standard HTTP client. The attacker needs no knowledge of internal state — sending `timestamp=gte:0` is sufficient. The attack is trivially repeatable and scriptable from multiple IPs, making sustained degradation straightforward.

### Recommendation

1. **Remove `validateRange=false` from the `getTransactions` call** (`rest/transactions.js:674`). Change the sixth argument to `true` so `maxTimestampRangeNs` is enforced. If a wider range than 7 days is intentional for this endpoint, introduce a separate `maxTransactionsTimestampRangeNs` check directly in `parseTimestampFilters` or validate it explicitly before calling `getTransactionTimestamps`.

2. **Enable `bindTimestampRange` by default** or make it a hard enforcement (not opt-in) for the `/transactions` endpoint. The current design makes the only effective range cap an opt-in operator setting, which is unsafe as a security control.

3. **Reject open-ended ranges** (`allowOpenRange=true`) for the public `/transactions` endpoint, or require both bounds to be present and within the allowed width.

### Proof of Concept

```bash
# Default deployment (bindTimestampRange=false, validateRange bypassed)

# 1. Fully open lower-bound range — scans entire transaction history
curl "https://<mirror-node>/api/v1/transactions?timestamp=gte:0"

# 2. Explicit maximum-width range (years of data)
curl "https://<mirror-node>/api/v1/transactions?timestamp=gte:0&timestamp=lte:9999999999.999999999"

# 3. Sustained attack — exhaust the 10-connection DB pool
for i in $(seq 1 20); do
  curl "https://<mirror-node>/api/v1/transactions?timestamp=gte:0" &
done
wait
# All other API endpoints now queue/timeout for up to 20s per wave
```

### Citations

**File:** rest/transactions.js (L463-468)
```javascript
  let nextTimestamp;
  if (timestampRange.eqValues.length === 0) {
    const {range, next} = await bindTimestampRange(timestampRange.range, order);
    timestampRange.range = range;
    nextTimestamp = next;
  }
```

**File:** rest/transactions.js (L483-483)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
```

**File:** rest/transactions.js (L671-677)
```javascript
const getTransactions = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedTransactionParameters);
  const timestampFilters = filters.filter((filter) => filter.key === constants.filterKeys.TIMESTAMP);
  const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);

  res.locals[constants.responseDataLabel] = await doGetTransactions(filters, req, timestampRange);
};
```

**File:** rest/utils.js (L1651-1653)
```javascript
  if (!allowOpenRange && eqValues.size === 0 && (lowerBoundFilterCount === 0 || upperBoundFilterCount === 0)) {
    throw new InvalidArgumentError('Timestamp range must have gt (or gte) and lt (or lte), or eq operator');
  }
```

**File:** rest/utils.js (L1657-1666)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
  }
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```

**File:** docs/configuration.md (L555-557)
```markdown
| `hiero.mirror.rest.db.pool.connectionTimeout`                            | 20000                   | The number of milliseconds to wait before timing out when connecting a new database client                                                                                                    |
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** docs/configuration.md (L579-579)
```markdown
| `hiero.mirror.rest.query.bindTimestampRange`                             | false                   | Whether to bind the timestamp range to maxTimestampRange                                                                                                                                      |
```
