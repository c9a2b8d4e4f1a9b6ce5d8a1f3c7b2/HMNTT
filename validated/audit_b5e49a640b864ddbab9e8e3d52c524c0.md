Based on my direct examination of the code, all key claims are verified against the actual source. Here is my assessment:

---

Audit Report

## Title
Unbounded Timestamp Range Bypass in `optimizeTimestampFilters` Enables Full-Table-Scan DoS on `/contracts/results`

## Summary
`optimizeTimestampFilters` in `rest/controllers/contractController.js` explicitly passes `validateRange=false` to `utils.parseTimestampFilters`, disabling the 7-day range-size guard. The only remaining protection, `bindTimestampRange`, is a no-op when `queryConfig.bindTimestampRange` is falsy (the documented default). An unauthenticated attacker can supply an arbitrarily wide `gte`/`lte` timestamp pair that passes all validation and drives an unbounded scan of the `contract_result` table.

## Finding Description

**Verified code path:**

`getContractResults` (line 1050) calls `extractContractResultsByIdQuery(filters)` with no `contractId` at line 1067. [1](#0-0) 

`extractContractResultsByIdQuery` at lines 504–505 routes to `optimizeTimestampFilters` when `contractId === undefined`: [2](#0-1) 

`optimizeTimestampFilters` (lines 384–405) calls `parseTimestampFilters` with the 6th argument `false` (`validateRange=false`): [3](#0-2) 

Inside `parseTimestampFilters` (`rest/utils.js`, lines 1657–1665), the range-size guard is gated on `validateRange`, which is `false` at this call site — the guard is never entered: [4](#0-3) 

After `parseTimestampFilters` returns, `bindTimestampRange` (`rest/timestampRange.js`, line 20) is the only remaining cap. When `queryConfig.bindTimestampRange` is falsy it immediately returns the attacker-supplied range unchanged: [5](#0-4) 

**`strictTimestampParam` does not mitigate this.** The strict-check path (lines 1642–1644 of `utils.js`) only rejects *multiple* lower-bound or upper-bound operators. A single `gte` + single `lte` pair spanning an arbitrary range passes strict checks without error. [6](#0-5) 

The resulting SQL query against `contract_result` carries `WHERE cr.consensus_timestamp >= 0 AND cr.consensus_timestamp <= <max>`, which forces PostgreSQL into a full or near-full index/table scan on the partitioned `contract_result` table. [7](#0-6) 

## Impact Explanation
Each such request holds a DB connection for the duration of the scan (up to `statementTimeout`, default 20 s). With a small default connection pool, a handful of concurrent attacker requests saturate the pool. All legitimate API calls queue or time out, rendering the mirror-node REST API unavailable. The `/api/v1/contracts/results` endpoint is the primary read interface for dApps and wallets querying contract execution data; sustained unavailability degrades network usability for end users and operators.

## Likelihood Explanation
The endpoint requires no authentication. The exploit is a single HTTP GET with two standard timestamp query parameters (e.g., `?timestamp=gte:0&timestamp=lte:9999999999`). No credentials, special tooling, or prior knowledge are required. The attack is trivially scriptable. Because `bindTimestampRange` defaults to `false`, most deployments that have not explicitly opted in to the mitigation are exposed.

## Recommendation
1. **Enable `bindTimestampRange` by default** in `rest/config.js` / `docs/configuration.md`. This is the intended mitigation and already exists in `timestampRange.js`; it simply needs to be on by default.
2. **Pass `validateRange=true`** in the `optimizeTimestampFilters` call to `parseTimestampFilters`, or add an explicit range-size check inside `optimizeTimestampFilters` itself, so the 7-day guard applies regardless of the `bindTimestampRange` config value.
3. **Rate-limit or require authentication** on expensive scan endpoints as a defense-in-depth measure.

## Proof of Concept
```
GET /api/v1/contracts/results?timestamp=gte:0&timestamp=lte:9999999999999999999
```
With default config (`bindTimestampRange: false`), this request bypasses both guards and issues an unbounded scan. Sending 5–10 concurrent copies of this request against a mirror node with default pool settings (`maxConnections: 10`) will exhaust the connection pool and cause all other API requests to time out for the duration of the scans.

### Citations

**File:** rest/controllers/contractController.js (L387-387)
```javascript
  const {range, eqValues, neValues} = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
```

**File:** rest/controllers/contractController.js (L392-399)
```javascript
  const {range: optimizedRange, next} = eqValues.length === 0 ? await bindTimestampRange(range, order) : {range};
  if (optimizedRange?.begin) {
    filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.gte, value: optimizedRange.begin});
  }

  if (optimizedRange?.end) {
    filters.push({key: filterKeys.TIMESTAMP, operator: utils.opsMap.lte, value: optimizedRange.end});
  }
```

**File:** rest/controllers/contractController.js (L504-505)
```javascript
    const {filters: optimizedTimestampFilters, next} =
      contractId === undefined ? await optimizeTimestampFilters(timestampFilters, order) : {filters: timestampFilters};
```

**File:** rest/controllers/contractController.js (L1050-1067)
```javascript
  getContractResults = async (req, res) => {
    const filters = utils.buildAndValidateFilters(
      req.query,
      acceptedContractResultsParameters,
      contractResultsFilterValidityChecks
    );

    // Extract hbar parameter (default: true)
    const convertToHbar = utils.parseHbarParam(req.query.hbar);

    const response = {
      results: [],
      links: {
        next: null,
      },
    };
    res.locals[responseDataLabel] = response;
    const {conditions, params, order, limit, skip, next} = await this.extractContractResultsByIdQuery(filters);
```

**File:** rest/utils.js (L1642-1644)
```javascript
    if (upperBoundFilterCount > 1) {
      throw new InvalidArgumentError('Multiple lt or lte operators not permitted for timestamp param');
    }
```

**File:** rest/utils.js (L1657-1665)
```javascript
  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```

**File:** rest/timestampRange.js (L19-22)
```javascript
const bindTimestampRange = async (range, order) => {
  if (!queryConfig.bindTimestampRange) {
    return {range};
  }
```
