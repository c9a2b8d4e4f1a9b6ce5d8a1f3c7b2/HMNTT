### Title
Unauthenticated Amplified DB Query Fan-Out in `getContractResults` Enables Non-Network DoS

### Summary
The `getContractResults` handler in `rest/controllers/contractController.js` allows any unauthenticated caller to trigger three database queries per request: one primary query bounded by `limit`, followed by two parallel secondary queries (`getEthereumTransactionsByPayerAndTimestampArray` and `getRecordFileBlockDetailsFromTimestampArray`) whose array parameters are sized exactly equal to the number of rows returned (up to the configured maximum limit of 100). Because no authentication or rate limiting is enforced, an attacker can flood this endpoint with `limit=100` requests, causing sustained amplified DB load proportional to the limit on every request.

### Finding Description

**Exact code path:**

`rest/controllers/contractController.js`, `getContractResults`, lines 1050–1112:

```
1072: const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
1077: const payers = [];
1078: const timestamps = [];
1079: rows.forEach((row) => {
1080:   payers.push(row.payerAccountId);
1081:   timestamps.push(row.consensusTimestamp);
1082: });
1083: const [ethereumTransactionMap, recordFileMap] = await Promise.all([
1084:   ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
1085:   RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
1086: ]);
```

**Root cause:** After the primary paginated query returns up to `limit` rows, the handler unconditionally builds `payers[]` and `timestamps[]` arrays of size `rows.length` (≤ `limit`) and passes them to two parallel DB queries. There is no guard, cache, or deduplication before issuing these secondary queries.

**Secondary query 1 — `getEthereumTransactionsByPayerAndTimestampArray`** (`rest/service/contractService.js`, lines 519–546): passes the full `payers` and `timestamps` arrays as PostgreSQL array parameters, performing an `IN`-style lookup across up to 100 payer/timestamp pairs.

**Secondary query 2 — `getRecordFileBlockDetailsFromTimestampArray`** (`rest/service/recordFileService.js`, lines 23–43): uses a correlated subquery with `unnest($1::bigint[])` — for each timestamp in the array it executes an inner `SELECT … ORDER BY … LIMIT 1` against `record_file`. This is O(N) in the array size at the DB level.

**Max limit:** The default configuration exposes `max: 100` (confirmed in `rest/__tests__/config.test.js` line 324). No authentication is required to reach this endpoint (`acceptedContractResultsParameters` contains only `FROM`, `BLOCK_HASH`, `BLOCK_NUMBER`, `HBAR`, `INTERNAL`, `LIMIT`, `ORDER`, `TIMESTAMP`, `TRANSACTION_INDEX` — no auth filter).

**Why checks fail:** `buildAndValidateFilters` only validates parameter types and enforces the max limit ceiling. It does not rate-limit callers, require credentials, or throttle concurrent requests. The `skip` early-return only fires when timestamp range optimization produces an empty set — it does not fire for a full-page result.

### Impact Explanation

Each `GET /contracts/results?limit=100` request causes:
1. One primary DB query returning up to 100 rows.
2. Two parallel secondary DB queries with 100-element array parameters, one of which (`getRecordFileBlockDetailsFromTimestampArray`) executes a correlated subquery 100 times inside the DB engine.

An attacker sending C concurrent requests per second sustains `3×C` DB queries/second, with the correlated subquery in query 2 multiplying internal DB work by up to 100×. This can exhaust DB connection pool slots, CPU, and I/O on the database server, degrading or denying service to all users. The Node.js process also accumulates in-memory arrays and Maps proportional to `limit × C`.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and only a standard HTTP client. The endpoint is publicly documented in `rest/api/v1/openapi.yml`. A single attacker with modest bandwidth (the requests are tiny GET queries) can sustain the amplified DB load. The attack is trivially repeatable and scriptable (e.g., `while true; do curl .../contracts/results?limit=100 & done`).

### Recommendation

1. **Rate limiting:** Enforce per-IP (and optionally global) request rate limits on this endpoint before DB queries are issued.
2. **Reduce secondary query fan-out:** Cache or batch `getRecordFileBlockDetailsFromTimestampArray` results; the correlated subquery should be rewritten as a range join to avoid O(N) inner selects.
3. **Lower the effective max limit** for the unauthenticated path, or require authentication for `limit` values above a safe threshold (e.g., 25).
4. **Connection pool protection:** Set a per-request DB query timeout and limit the number of concurrent in-flight requests to this handler.

### Proof of Concept

**Preconditions:** A running mirror-node REST API with at least one `contract_result` row in the DB. No credentials needed.

**Trigger:**
```bash
# Single amplified request (3 DB queries, correlated subquery runs 100 times)
curl "https://<mirror-node>/api/v1/contracts/results?limit=100"

# Flood attack (sustained amplified DB load)
for i in $(seq 1 200); do
  curl -s "https://<mirror-node>/api/v1/contracts/results?limit=100" &
done
wait
```

**Result:** Each concurrent request causes the DB to execute the correlated `unnest`-based subquery up to 100 times in parallel across all in-flight requests. DB CPU, connection pool, and I/O spike proportionally to the number of concurrent attackers, degrading or denying service to legitimate users. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/contractController.js (L1072-1086)
```javascript
    const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
    if (rows.length === 0) {
      return;
    }

    const payers = [];
    const timestamps = [];
    rows.forEach((row) => {
      payers.push(row.payerAccountId);
      timestamps.push(row.consensusTimestamp);
    });
    const [ethereumTransactionMap, recordFileMap] = await Promise.all([
      ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
      RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
    ]);
```

**File:** rest/service/contractService.js (L519-546)
```javascript
  async getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps) {
    const transactionMap = new Map();
    if (isEmpty(payers) || isEmpty(timestamps)) {
      return transactionMap;
    }

    let maxTimestamp = -1n;
    let minTimestamp = MAX_LONG;
    timestamps.forEach((timestamp) => {
      if (timestamp > maxTimestamp) {
        maxTimestamp = timestamp;
      }
      if (timestamp < minTimestamp) {
        minTimestamp = timestamp;
      }
    });

    const rows = await super.getRows(ContractService.ethereumTransactionByPayerAndTimestampArrayQuery, [
      payers,
      timestamps,
      minTimestamp,
      maxTimestamp,
    ]);

    rows.forEach((row) => transactionMap.set(row.consensus_timestamp, new EthereumTransaction(row)));

    return transactionMap;
  }
```

**File:** rest/service/recordFileService.js (L23-43)
```javascript
  static recordFileBlockDetailsFromTimestampArrayQuery = `select
      ${RecordFile.CONSENSUS_END},
      ${RecordFile.CONSENSUS_START},
      ${RecordFile.INDEX},
      ${RecordFile.HASH},
      ${RecordFile.GAS_USED}
    from ${RecordFile.tableName}
    where ${RecordFile.CONSENSUS_END} in (
      select
       (
         select ${RecordFile.CONSENSUS_END}
         from ${RecordFile.tableName}
         where ${RecordFile.CONSENSUS_END} >= timestamp and
           ${RecordFile.CONSENSUS_END} >= $2 and
           ${RecordFile.CONSENSUS_END} <= $3
         order by ${RecordFile.CONSENSUS_END}
         limit 1
       ) as consensus_end
    from (select unnest($1::bigint[]) as timestamp) as tmp
      group by consensus_end
    ) and ${RecordFile.CONSENSUS_END} >= $2 and ${RecordFile.CONSENSUS_END} <= $3`;
```

**File:** rest/service/recordFileService.js (L92-103)
```javascript
  async getRecordFileBlockDetailsFromTimestampArray(timestamps) {
    const recordFileMap = new Map();
    if (timestamps.length === 0) {
      return recordFileMap;
    }

    const {maxTimestamp, minTimestamp, order} = this.getTimestampArrayContext(timestamps);
    const query = `${RecordFileService.recordFileBlockDetailsFromTimestampArrayQuery}
      order by consensus_end ${order}`;
    const params = [timestamps, minTimestamp, BigInt(maxTimestamp) + config.query.maxRecordFileCloseIntervalNs];

    const rows = await super.getRows(query, params);
```

**File:** rest/__tests__/config.test.js (L321-325)
```javascript
describe('getResponseLimit', () => {
  test('default', async () => {
    const func = (await import('../config')).getResponseLimit;
    expect(func()).toEqual({default: 25, max: 100, tokenBalance: {multipleAccounts: 50, singleAccount: 1000}});
  });
```
