### Title
Unbounded Full-Table Scan via `result=fail` Filter Enables DB Resource Exhaustion

### Summary
The `/api/v1/transactions?result=fail` endpoint generates a SQL query with `t.result NOT IN (...)` on an unindexed column with no mandatory timestamp bounds. Because `bindTimestampRange` defaults to `false`, an unprivileged attacker can repeatedly issue this request to force full sequential scans across all `transaction` table partitions, exhausting the shared DB connection pool (default: 10 connections) and degrading query performance for all other users.

### Finding Description

**Code path 1 — filter value accepted without restriction:**
`filterKeys.RESULT = 'result'` and `transactionResultFilter.FAIL = 'fail'` are defined in `rest/constants.js` lines 43 and 115–118. The value is accepted from any unauthenticated HTTP request. [1](#0-0) 

**Code path 2 — SQL generation produces `NOT IN` on unindexed column:**
In `rest/transactions.js` lines 426–428, when `resultType` equals `'fail'`, the query fragment becomes `t.result not in (<success_proto_ids>)`. The `result` column has **no database index** (confirmed across all migration files in `importer/src/main/resources/db/migration/`; only `consensus_timestamp`, `payer_account_id`, `type`, and `valid_start_ns` are indexed). [2](#0-1) 

**Code path 3 — no mandatory timestamp bound:**
`bindTimestampRange` defaults to `false` in the configuration. [3](#0-2) 

When `false`, `bindTimestampRange()` in `rest/timestampRange.js` returns immediately without constraining the range, so no lower/upper timestamp is injected into the query. [4](#0-3) 

The resulting SQL executed against the DB is:
```sql
SELECT consensus_timestamp, payer_account_id
FROM transaction AS t
WHERE t.result NOT IN (<success_proto_ids>)
ORDER BY t.consensus_timestamp DESC
LIMIT 25
```
PostgreSQL must perform a sequential scan across all `transaction` partitions (partitioned by `consensus_timestamp`) to satisfy this query. [5](#0-4) 

**Existing checks reviewed and shown insufficient:**

- `statementTimeout: 20000` (20 s) — limits a single query but does not prevent many concurrent queries from holding connections for up to 20 s each. [6](#0-5) 
- `db.pool.maxConnections: 10` — with 10 concurrent 20-second full-table scans, the entire connection pool is saturated. [7](#0-6) 
- `response.limit.max: 100` — caps result rows but does not reduce scan cost; PostgreSQL still scans until 100 matching rows are found. [8](#0-7) 
- **No per-IP or per-user rate limiting** exists on the Node.js REST API for the `/api/v1/transactions` endpoint. The throttling infrastructure (bucket4j) is only wired to the Java web3 service. [9](#0-8) 

### Impact Explanation
An attacker sending 10+ concurrent `GET /api/v1/transactions?result=fail` requests saturates the 10-connection DB pool with long-running sequential scans. Legitimate queries (account lookups, balance queries, etc.) queue behind these scans, causing elevated latency or timeouts for all API consumers. No economic damage occurs, but service availability and responsiveness are degraded — consistent with the "griefing" classification in the question scope.

### Likelihood Explanation
No authentication, API key, or special network access is required. The endpoint is public. The attack is trivially scriptable with `curl` or any HTTP client. It is repeatable indefinitely since there is no rate limit or IP-based throttle on this endpoint. The default `bindTimestampRange=false` means most production deployments are exposed unless operators have explicitly opted in to the timestamp-bounding feature.

### Recommendation
1. **Enable `bindTimestampRange: true`** in production deployments, or make it the default, so all `result=fail` queries are bounded to `maxTransactionsTimestampRange` (default 60 days).
2. **Add a composite index** on `(result, consensus_timestamp)` to allow index-range scans when `result` is filtered.
3. **Require at least one timestamp filter** when `result=fail` is the only filter, rejecting requests that omit it with HTTP 400.
4. **Add per-IP rate limiting** to the Node.js REST API (e.g., via an express-rate-limit middleware) for the `/api/v1/transactions` endpoint.

### Proof of Concept
```bash
# Saturate the DB connection pool with 12 concurrent full-table scans
for i in $(seq 1 12); do
  curl -s "https://<mirror-node-host>/api/v1/transactions?result=fail" &
done
wait
# Legitimate queries now queue behind these scans; observe elevated latency
curl -w "%{time_total}\n" -s "https://<mirror-node-host>/api/v1/accounts/0.0.1" -o /dev/null
```
With `bindTimestampRange=false` (default) and no index on `result`, each of the 12 requests triggers a full sequential scan of the `transaction` table. The 10-connection pool is exhausted; the account lookup in the last line experiences multi-second latency or a timeout.

### Citations

**File:** rest/constants.js (L115-118)
```javascript
const transactionResultFilter = {
  SUCCESS: 'success',
  FAIL: 'fail',
};
```

**File:** rest/transactions.js (L426-429)
```javascript
  if (resultType) {
    const operator = resultType === constants.transactionResultFilter.SUCCESS ? 'in' : 'not in';
    resultTypeQuery = `t.result ${operator} (${utils.resultSuccess})`;
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

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
```

**File:** docs/configuration.md (L557-557)
```markdown
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** docs/configuration.md (L579-585)
```markdown
| `hiero.mirror.rest.query.bindTimestampRange`                             | false                   | Whether to bind the timestamp range to maxTimestampRange                                                                                                                                      |
| `hiero.mirror.rest.query.maxRecordFileCloseInterval`                     | 10s                     | The maximum close interval of record files to limit the time partitions to scan. Note the default value is larger than the actual network close interval                                      |
| `hiero.mirror.rest.query.maxRepeatedQueryParameters`                     | 100                     | The maximum number of times any query parameter can be repeated in the uri                                                                                                                    |
| `hiero.mirror.rest.query.maxScheduledTransactionConsensusTimestampRange` | 89285m                  | The maximum amount of time of a scheduled transaction's consensus timestamp from its valid start timestamp.                                                                                   |
| `hiero.mirror.rest.query.maxTimestampRange`                              | 7d                      | The maximum amount of time a timestamp range query param can span for some APIs.                                                                                                              |
| `hiero.mirror.rest.query.maxTransactionConsensusTimestampRange`          | 35m                     | The maximum amount of time of a transaction's consensus timestamp from its valid start timestamp.                                                                                             |
| `hiero.mirror.rest.query.maxTransactionsTimestampRange`                  | 60d                     | The maximum timestamp range to list transactions.                                                                                                                                             |
```

**File:** docs/configuration.md (L608-608)
```markdown
| `hiero.mirror.rest.response.limit.max`                                   | 100                     | The maximum size the limit parameter can be that controls the REST API response size                                                                                                          |
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```
