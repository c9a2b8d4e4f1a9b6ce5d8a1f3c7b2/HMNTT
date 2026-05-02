### Title
Unauthenticated Request Amplification via `getContractResults()` Triggering Three Unbounded DB Queries Per Request

### Summary
The `GET /api/v1/contracts/results` endpoint, handled by `getContractResults()`, requires no authentication and no mandatory filters. A single request with `limit=100` (the default maximum) causes three sequential/parallel database queries — one primary and two secondary — where the secondary queries receive arrays sized proportionally to the result set. An attacker can flood this endpoint concurrently to amplify database load with no economic cost.

### Finding Description

**Code path:** `rest/controllers/contractController.js`, `getContractResults()`, lines 1050–1112.

**Step 1 — Primary query (line 1072):**
```js
const rows = await ContractService.getContractResultsByIdAndFilters(conditions, params, order, limit);
```
`limit` is taken directly from the user-supplied `limit` query parameter, capped at `config.response.limit.max` (default: **100**). No authentication or mandatory filter is required.

**Step 2 — Array construction (lines 1077–1082):**
```js
rows.forEach((row) => {
  payers.push(row.payerAccountId);
  timestamps.push(row.consensusTimestamp);
});
```
Both arrays grow to exactly `rows.length` (up to 100 elements).

**Step 3 — Two additional parallel DB queries (lines 1083–1086):**
```js
const [ethereumTransactionMap, recordFileMap] = await Promise.all([
  ContractService.getEthereumTransactionsByPayerAndTimestampArray(payers, timestamps),
  RecordFileService.getRecordFileBlockDetailsFromTimestampArray(timestamps),
]);
```

The `recordFileBlockDetailsFromTimestampArrayQuery` (defined in `rest/service/recordFileService.js`, lines 23–43) uses a **correlated subquery** inside an `unnest()`:
```sql
where consensus_end in (
  select (
    select consensus_end from record_file
    where consensus_end >= timestamp and ...
    order by consensus_end limit 1
  ) as consensus_end
  from (select unnest($1::bigint[]) as timestamp) as tmp
  group by consensus_end
)
```
This correlated subquery executes once per unique timestamp in the array — up to 100 index lookups per request.

**Why existing checks are insufficient:**
- `extractContractResultsByIdQuery` (line 415) caps `limit` at `responseLimit.max` (100), but this only bounds the array size, not the number of requests.
- `optimizeTimestampFilters` (line 504) calls `bindTimestampRange` when no timestamp is provided, which may add a default window, but the primary query still returns up to 100 rows and the secondary queries still fire unconditionally.
- There is no authentication requirement, no rate limiting, and no mandatory filter on this endpoint.

### Impact Explanation
Each unauthenticated request with `limit=100` and no filters triggers **3 database queries**, with the `record_file` correlated subquery performing up to 100 index lookups internally. Concurrent flooding of this endpoint multiplies DB load linearly. At 100 concurrent requests, the database receives 300 queries simultaneously, with the `record_file` query alone performing up to 10,000 correlated subquery executions. This can degrade response times for all API consumers and exhaust DB connection pools, constituting a griefing denial-of-service with no economic cost to the attacker.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no on-chain activity. Any external user who discovers the public REST API can execute it with a simple HTTP client in a loop. The endpoint is publicly documented and accessible. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Rate limiting**: Apply per-IP or global rate limiting on `GET /contracts/results` at the API gateway or middleware layer.
2. **Mandatory timestamp filter**: Require at least one timestamp filter (e.g., `timestamp=gte:X`) when no `contractId` is provided, similar to how other list endpoints enforce time-bounded queries.
3. **Reduce secondary query cost**: Replace the correlated subquery in `recordFileBlockDetailsFromTimestampArrayQuery` with a lateral join or a range-based lookup to avoid per-timestamp correlated execution.
4. **Authentication for high-limit requests**: Require authentication for requests with `limit` above a lower threshold (e.g., 25) on this endpoint.

### Proof of Concept

```bash
# Single amplified request (3 DB queries, up to 100 correlated subquery executions in record_file)
curl "https://<mirror-node-host>/api/v1/contracts/results?limit=100"

# Concurrent flood (no credentials required)
for i in $(seq 1 100); do
  curl -s "https://<mirror-node-host>/api/v1/contracts/results?limit=100" &
done
wait
# Result: 300 DB queries fired simultaneously; record_file correlated subquery
# executes up to 10,000 times across all concurrent requests.
```

**Preconditions:** Public network access to the mirror node REST API. No account, token, or privileged access required.
**Trigger:** `GET /api/v1/contracts/results?limit=100` with no other filters.
**Result:** Three DB queries per request, with the `record_file` correlated subquery amplifying internal DB work proportionally to the result set size. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/controllers/contractController.js (L415-457)
```javascript
  extractContractResultsByIdQuery = async (filters, contractId = undefined) => {
    let limit = defaultLimit;
    let order = orderFilterValues.DESC;
    const conditions = [];
    const params = [];
    if (contractId) {
      conditions.push(`${ContractResult.getFullName(ContractResult.CONTRACT_ID)} = $1`);
      params.push(contractId);
    }

    let internal = false;

    const contractResultSenderFullName = ContractResult.getFullName(ContractResult.SENDER_ID);
    const contractResultFromInValues = [];

    const contractResultTimestampFullName = ContractResult.getFullName(ContractResult.CONSENSUS_TIMESTAMP);
    const contractResultTimestampInValues = [];

    const transactionIndexFullName = ContractResult.getFullName(ContractResult.TRANSACTION_INDEX);
    const transactionIndexInValues = [];

    let blockFilter;
    const timestampFilters = [];

    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.FROM:
          // Evm addresses are not parsed by utils.buildAndValidateFilters, so they are converted to encoded ids here.
          if (EntityId.isValidEvmAddress(filter.value)) {
            filter.value = await EntityService.getEncodedId(filter.value);
          }
          this.updateConditionsAndParamsWithInValues(
            filter,
            contractResultFromInValues,
            params,
            conditions,
            contractResultSenderFullName,
            conditions.length + 1
          );
          break;
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
```

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

**File:** rest/service/contractService.js (L179-199)
```javascript
  static ethereumTransactionByPayerAndTimestampArrayQuery = `select
        encode(${EthereumTransaction.ACCESS_LIST}, 'hex') ${EthereumTransaction.ACCESS_LIST},
        ${EthereumTransaction.AUTHORIZATION_LIST},
        encode(${EthereumTransaction.CHAIN_ID}, 'hex') ${EthereumTransaction.CHAIN_ID},
        ${EthereumTransaction.CONSENSUS_TIMESTAMP},
        encode(${EthereumTransaction.GAS_PRICE}, 'hex') ${EthereumTransaction.GAS_PRICE},
        encode(${EthereumTransaction.MAX_FEE_PER_GAS}, 'hex') ${EthereumTransaction.MAX_FEE_PER_GAS},
        encode(${EthereumTransaction.MAX_PRIORITY_FEE_PER_GAS}, 'hex') ${EthereumTransaction.MAX_PRIORITY_FEE_PER_GAS},
        ${EthereumTransaction.NONCE},
        encode(${EthereumTransaction.SIGNATURE_R}, 'hex') ${EthereumTransaction.SIGNATURE_R},
        encode(${EthereumTransaction.SIGNATURE_S}, 'hex') ${EthereumTransaction.SIGNATURE_S},
        ${EthereumTransaction.SIGNATURE_V},
        ${EthereumTransaction.TYPE},
        ${EthereumTransaction.RECOVERY_ID},
        encode(${EthereumTransaction.TO_ADDRESS}, 'hex') ${EthereumTransaction.TO_ADDRESS},
        encode(${EthereumTransaction.VALUE}, 'hex') ${EthereumTransaction.VALUE}
      from ${EthereumTransaction.tableName}
      where ${EthereumTransaction.PAYER_ACCOUNT_ID} = any($1)
        and ${EthereumTransaction.CONSENSUS_TIMESTAMP} = any($2)
        and ${EthereumTransaction.CONSENSUS_TIMESTAMP} >= $3
        and ${EthereumTransaction.CONSENSUS_TIMESTAMP} <= $4`;
```
