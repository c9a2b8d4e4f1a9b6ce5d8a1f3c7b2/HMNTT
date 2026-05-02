### Title
Unbounded Timestamp Range in `getContractById` Triggers Full `entity_history` Table Scan via UNION Query

### Summary
`getContractById()` in `rest/controllers/contractController.js` accepts arbitrary `timestamp=gte:A&timestamp=lte:B` query parameters and passes them directly to `getContractByIdOrAddressContractEntityQuery()`, which UNIONs both the `entity` and `entity_history` tables when any timestamp condition is present. Unlike other endpoints, this code path never calls `parseTimestampFilters()` (which enforces `maxTimestampRangeNs`), so an unauthenticated attacker can supply an arbitrarily wide timestamp range, forcing a full scan of the unbounded `entity_history` table on every request.

### Finding Description

**Exact code path:**

`rest/routes/contractRoute.js` line 13 routes `GET /:contractId` to `ContractController.getContractById`.

`getContractById()` at `rest/controllers/contractController.js:707-737`:
- Line 712–715: calls `extractContractIdAndFiltersFromValidatedRequest(req, acceptedContractByIdParameters)`, where `acceptedContractByIdParameters = new Set([filterKeys.TIMESTAMP])` (line 1332). This calls `utils.buildAndValidateFilters` → `filterValidityChecks`, which for `TIMESTAMP` only checks `isValidTimestampParam(val)` — format validation only, no range-width check.
- Lines 717–718: calls `utils.extractTimestampRangeConditionFilters(filters)`. This function (`rest/utils.js:709-756`) converts each timestamp filter to a pg `Range` object and returns conditions/params. **It performs zero range-width validation.**
- Lines 720–724: passes the conditions to `getContractByIdOrAddressContractEntityQuery()`.

`getContractByIdOrAddressContractEntityQuery()` at `rest/controllers/contractController.js:179-208`:
- Line 193: always queries `entity` table.
- Lines 194–201: **if `timestampConditions.length !== 0`** (triggered by any timestamp filter), it appends `UNION … entity_history … order by timestamp_range desc limit 1`. The `limit 1` applies only to the final UNION result, not to the individual `entity_history` scan.

The generated SQL for `GET /contracts/0.0.1?timestamp=gte:0&timestamp=lte:9999999999999999` becomes:
```sql
SELECT ... FROM entity e LEFT JOIN contract c ON e.id = c.id
WHERE e.type = 'CONTRACT' AND c.timestamp_range && $1 AND c.timestamp_range && $2 AND e.id = $3
UNION
SELECT ... FROM entity_history e LEFT JOIN contract c ON e.id = c.id
WHERE e.type = 'CONTRACT' AND c.timestamp_range && $1 AND c.timestamp_range && $2 AND e.id = $3
ORDER BY timestamp_range DESC LIMIT 1
```
With `$1 = Range(0, null, '[)')` and `$2 = Range(null, 9999999999999999, '(]')`, both conditions overlap with every row in `entity_history`, forcing a full table scan.

**Root cause / failed assumption:** The developer assumed timestamp range width would be validated before reaching this query builder. The validation exists in `parseTimestampFilters()` (`rest/utils.js:1657-1665`, checks `maxTimestampRangeNs`) and in `optimizeTimestampFilters()` (`rest/controllers/contractController.js:384-405`, calls `bindTimestampRange`), but **neither is called in the `getContractById` code path**. Only `extractTimestampRangeConditionFilters` is called, which has no such guard.

### Impact Explanation
The `entity_history` table grows unboundedly as contracts are created, updated, and deleted over the network's lifetime. A full scan of this table on every request exhausts PostgreSQL I/O bandwidth and CPU, degrading or completely blocking all other mirror node queries. Because the endpoint returns at most one row, the attacker receives a normal 200 or 404 response, making the attack invisible without DB-level monitoring. This constitutes a non-network-based DoS against the mirror node's database tier.

### Likelihood Explanation
The endpoint is fully public and requires no authentication or special privileges. The attack requires only a valid contract ID (any existing `0.0.X` ID) and two timestamp parameters with valid format. It is trivially scriptable and repeatable at high frequency. A single attacker with a modest HTTP client can sustain the attack indefinitely.

### Recommendation
In `getContractById()`, after extracting timestamp filters, call `parseTimestampFilters()` with `validateRange = true` (the default) before passing them to `getContractByIdOrAddressContractEntityQuery()`. Specifically, add a call analogous to what `optimizeTimestampFilters` does:

```js
// After extracting filters, before building the query:
const timestampFilters = filters.filter(f => f.key === filterKeys.TIMESTAMP);
if (timestampFilters.length > 0) {
  utils.parseTimestampFilters(timestampFilters, false, false, true, true, true);
}
```

This enforces `maxTimestampRangeNs` and rejects open-ended or excessively wide ranges with a 400 error before any DB query is issued. Alternatively, route the timestamp filters through `optimizeTimestampFilters()` as other contract endpoints do.

### Proof of Concept

**Preconditions:** Mirror node REST API is reachable; at least one contract exists (e.g., `0.0.1`).

**Steps:**

1. Send a single request with a maximally wide timestamp range:
   ```
   GET /api/v1/contracts/0.0.1?timestamp=gte:0&timestamp=lte:9999999999999999
   ```
2. Observe that the request is accepted (no 400 error) and the server executes the UNION query against `entity_history` with no range restriction.
3. Repeat in a tight loop from a single client:
   ```bash
   while true; do
     curl -s "http://<mirror-node>/api/v1/contracts/0.0.1?timestamp=gte:0&timestamp=lte:9999999999999999" > /dev/null
   done
   ```
4. Monitor PostgreSQL: observe sequential scans on `entity_history` consuming I/O and CPU, causing latency spikes or timeouts on all other mirror node API endpoints.

**Expected result without fix:** Server accepts the request, executes full `entity_history` scan, returns 200/404. DB I/O saturates under repeated requests.

**Expected result with fix:** Server returns `HTTP 400 Invalid parameter: timestamp` before issuing any DB query.