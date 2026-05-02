### Title
Uncached Per-Request DB Lookup via Unprivileged `block.number` Filter in `extractContractResultsByIdQuery`

### Summary
Any unauthenticated user can supply a `block.number` query parameter to the `/api/v1/contracts/results` or `/api/v1/contracts/:contractId/results` endpoints. For every such request, `extractContractResultsByIdQuery` unconditionally calls `RecordFileService.getRecordFileBlockDetailsFromIndex()`, which issues a live database query with no caching. By cycling through distinct block numbers, an attacker forces a fresh DB round-trip on every request, amplifying database load without any privilege requirement.

### Finding Description
**Code path:**

`acceptedContractResultsParameters` (line 1339) includes `filterKeys.BLOCK_NUMBER`, making it a valid, accepted query parameter for both public endpoints.

`contractResultsFilterValidityChecks` (lines 273–279) only restricts the operator to `eq`; it does not gate or throttle the lookup itself:
```js
if (ret && param === filterKeys.BLOCK_NUMBER) {
  return op === queryParamOperators.eq;
}
```

Inside `extractContractResultsByIdQuery` (lines 486–489), when any `BLOCK_NUMBER` filter is present, the code unconditionally fires a live DB query:
```js
if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
  blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
}
```

`getRecordFileBlockDetailsFromIndex` (line 131–134 of `rest/service/recordFileService.js`) executes:
```sql
SELECT consensus_start, consensus_end, hash, index
FROM record_file
WHERE index = $1
LIMIT 1
```
There is no in-process cache wrapping this call. The response-level cache (`responseCacheHandler.js`) only helps for identical full requests; rotating the `block.number` value bypasses it entirely.

**Root cause:** The `BLOCK_NUMBER` filter path has no result cache and no application-level rate limit. The validation gate only enforces the `eq` operator, not the frequency or cost of the resulting lookup.

### Impact Explanation
Every HTTP request carrying a unique `block.number` value forces one extra synchronous DB query against the `record_file` table before the main contract-results query executes. A single attacker with a modest request rate (e.g., 1 000 req/s with rotating block numbers) doubles the effective DB query rate for this endpoint. Under sustained load this degrades or exhausts the database connection pool, causing latency spikes and potential unavailability of the mirror node REST API for all consumers.

### Likelihood Explanation
The endpoint is public and requires no authentication. The attack requires only an HTTP client and knowledge of the public API schema (documented). Block numbers are sequential integers, trivially enumerable. The attack is fully repeatable and automatable with standard tooling (curl, wrk, ab). No brute-force credential guessing is needed.

### Recommendation
1. **Cache the lookup result**: Wrap `getRecordFileBlockDetailsFromIndex` with a short-lived in-process or Redis cache keyed on the block index. Block-to-timestamp mappings are immutable once finalized, so a TTL of minutes is safe.
2. **Application-level rate limiting**: Apply per-IP or per-client rate limits specifically on endpoints that accept `block.number` / `block.hash` filters.
3. **Validate block number range**: Reject block numbers that exceed the current chain tip (obtainable cheaply from a cached latest-block value) before issuing the DB query.

### Proof of Concept
```bash
# Flood the endpoint with rotating block numbers, each forcing a fresh DB query
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/contracts/results?block.number=$i" &
done
wait
```
Each request with a distinct `block.number` bypasses the response cache and triggers `RecordFileService.getRecordFileBlockDetailsFromIndex($i)` → one live `SELECT … FROM record_file WHERE index = $i` query, in addition to the main contract-results query. Sustained parallel execution exhausts DB connections and degrades the service for all users. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/contractController.js (L273-279)
```javascript
const contractResultsFilterValidityChecks = (param, op, val) => {
  const ret = utils.filterValidityChecks(param, op, val);
  if (ret && param === filterKeys.BLOCK_NUMBER) {
    return op === queryParamOperators.eq;
  }
  return ret;
};
```

**File:** rest/controllers/contractController.js (L486-502)
```javascript
    if (blockFilter) {
      let blockData;
      if (blockFilter.key === filterKeys.BLOCK_NUMBER) {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromIndex(blockFilter.value);
      } else {
        blockData = await RecordFileService.getRecordFileBlockDetailsFromHash(blockFilter.value);
      }

      if (blockData) {
        timestampFilters.push(
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: blockData.consensusStart},
          {key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: blockData.consensusEnd}
        );
      } else {
        return {skip: true};
      }
    }
```

**File:** rest/controllers/contractController.js (L1336-1346)
```javascript
const acceptedContractResultsParameters = new Set([
  filterKeys.FROM,
  filterKeys.BLOCK_HASH,
  filterKeys.BLOCK_NUMBER,
  filterKeys.HBAR,
  filterKeys.INTERNAL,
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.TIMESTAMP,
  filterKeys.TRANSACTION_INDEX,
]);
```

**File:** rest/service/recordFileService.js (L52-56)
```javascript
  static recordFileBlockDetailsFromIndexQuery = `select
    ${RecordFile.CONSENSUS_START}, ${RecordFile.CONSENSUS_END}, ${RecordFile.HASH}, ${RecordFile.INDEX}
    from ${RecordFile.tableName}
    where  ${RecordFile.INDEX} = $1
    limit 1`;
```

**File:** rest/service/recordFileService.js (L131-135)
```javascript
  async getRecordFileBlockDetailsFromIndex(index) {
    const row = await super.getSingleRow(RecordFileService.recordFileBlockDetailsFromIndexQuery, [index]);

    return row === null ? null : new RecordFile(row);
  }
```
