### Title
Unbounded Timestamp Range Allows Full `transaction` Table Scan via `/api/v1/transactions` (DoS)

### Summary
`getTransactions()` in `rest/transactions.js` calls `parseTimestampFilters` with `validateRange=false`, explicitly disabling the `maxTimestampRange` (7-day) guard. The only remaining protection, `bindTimestampRange`, is **disabled by default** (`false`). An unauthenticated attacker can supply `timestamp=gte:0&timestamp=lte:9999999999999999999` to force a full scan of the `transaction` table, exhausting DB resources and causing sustained denial of service.

### Finding Description

**Exact code path:**

`getTransactions()` at `rest/transactions.js:674` calls:
```js
const timestampRange = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
``` [1](#0-0) 

The sixth argument is `validateRange=false`. Inside `parseTimestampFilters` (`rest/utils.js:1657-1666`), the range-size check against `maxTimestampRangeNs` (default 7 days) is gated on this flag:
```js
if (validateRange) {
  if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
    throw new InvalidArgumentError(...);
  }
}
``` [2](#0-1) 

Because `validateRange=false`, a range of `[0, 9999999999999999999]` passes through unchecked.

The range then reaches `getTransactionTimestamps()` at `rest/transactions.js:464-468`, which calls `bindTimestampRange`:
```js
const {range, next} = await bindTimestampRange(timestampRange.range, order);
``` [3](#0-2) 

`bindTimestampRange` in `rest/timestampRange.js:19-22` immediately returns the range unchanged when the feature flag is off:
```js
if (!queryConfig.bindTimestampRange) {
  return {range};
}
``` [4](#0-3) 

The default value of `bindTimestampRange` is `false`: [5](#0-4) 

The unbounded range is then used verbatim in the SQL query against the `transaction` table (and potentially `crypto_transfer`, `token_transfer`, `entity_transaction` via UNION/JOIN): [6](#0-5) 

**Root cause:** The design assumes `bindTimestampRange=true` will be the production guard, but the default is `false`, and no fallback range cap exists when it is disabled.

### Impact Explanation

With `bindTimestampRange=false` (the default), a single HTTP request causes PostgreSQL to execute a sequential scan (or index range scan spanning the entire table) over the `transaction` table plus up to three joined/unioned transfer tables. The DB connection pool (default 10 connections, `statementTimeout` 20 s) means an attacker can saturate all connections with ~10 concurrent requests, blocking all legitimate traffic for the duration of each query. Repeated requests create sustained DoS with no authentication required. [7](#0-6) 

### Likelihood Explanation

Preconditions: none beyond network access. The default deployment has `bindTimestampRange=false`. The attack requires only a standard HTTP GET with two query parameters. It is trivially scriptable, repeatable, and requires no knowledge of the system beyond the public API documentation. Any public-facing mirror node running the default configuration is vulnerable.

### Recommendation

1. **Immediate**: Remove `validateRange=false` from the `parseTimestampFilters` call in `getTransactions()` (`rest/transactions.js:674`), or add a separate explicit cap on the timestamp range before the DB query when `bindTimestampRange=false`.
2. **Preferred**: Change the default of `bindTimestampRange` to `true` so the `maxTransactionsTimestampRangeNs` (60-day) cap is always enforced.
3. **Defense-in-depth**: Add a hard upper bound on the timestamp range inside `getTransactionTimestamps()` that is independent of the `bindTimestampRange` feature flag.

### Proof of Concept

```
# No authentication required
curl "https://<mirror-node-host>/api/v1/transactions?timestamp=gte:0&timestamp=lte:9999999999999999999&limit=100"
```

1. Confirm the target has default config (`bindTimestampRange=false`).
2. Send the request above. The DB will execute a full-range scan of the `transaction` table.
3. Repeat ~10 times concurrently to saturate the connection pool (`maxConnections=10`).
4. Observe that all subsequent API requests time out or return 503 for the duration of the `statementTimeout` (20 s per query).
5. Loop to maintain sustained DoS.

### Citations

**File:** rest/transactions.js (L464-468)
```javascript
  if (timestampRange.eqValues.length === 0) {
    const {range, next} = await bindTimestampRange(timestampRange.range, order);
    timestampRange.range = range;
    nextTimestamp = next;
  }
```

**File:** rest/transactions.js (L537-553)
```javascript
  const transactionOnlyQuery = `
    select ${
      accountQuery
        ? `distinct on (${Transaction.getFullName(Transaction.CONSENSUS_TIMESTAMP)}, ${Transaction.getFullName(
            Transaction.PAYER_ACCOUNT_ID
          )})`
        : ''
    }
        ${Transaction.getFullName(Transaction.CONSENSUS_TIMESTAMP)},
        ${Transaction.getFullName(Transaction.PAYER_ACCOUNT_ID)}
    from (
        (select ${Transaction.CONSENSUS_TIMESTAMP}, ${Transaction.PAYER_ACCOUNT_ID}
         from ${Transaction.tableName} as ${Transaction.tableAlias} ${transactionWhereClause}
         order by ${Transaction.getFullName(Transaction.CONSENSUS_TIMESTAMP)} ${order} ${limitQuery})
        ${nftTransfersUnion}
    ) as ${Transaction.tableAlias}
    order by ${Transaction.getFullName(Transaction.CONSENSUS_TIMESTAMP)} ${order} ${limitQuery}`;
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
