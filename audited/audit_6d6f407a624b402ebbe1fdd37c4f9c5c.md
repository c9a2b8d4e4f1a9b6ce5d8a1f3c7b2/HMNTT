### Title
Unauthenticated Future-Timestamp DoS via Repeated Empty Index Scans on `consensus_end` in `/api/v1/blocks`

### Summary
The `getBlocks()` handler in `rest/controllers/blockController.js` accepts a `timestamp=gte:X` filter from any unauthenticated caller without validating that `X` is not a far-future value. Each such request causes `RecordFileService.getBlocks()` to execute a full index scan on `consensus_end` that returns zero rows. Repeated at high frequency, this exhausts DB connection pool slots and degrades service availability.

### Finding Description

**Exact code path:**

`getBlocks()` in `blockController.js` (lines 101–112) calls `utils.buildAndValidateFilters(req.query, acceptedBlockParameters)` with no custom validator, so the default `filterValidityChecks` is used. [1](#0-0) 

`filterValidityChecks` dispatches to `isValidTimestampParam(val)` for the `TIMESTAMP` key: [2](#0-1) 

`isValidTimestampParam` only validates format — up to 10 decimal digits for seconds and up to 9 for nanoseconds. It performs **no upper-bound or future-timestamp check**: [3](#0-2) 

A value like `9999999999` (year 2286) passes this regex. The filter is then forwarded to `extractSqlFromBlockFilters`, which maps it directly to a `WHERE consensus_end >= $1` clause with no further validation: [4](#0-3) 

`RecordFileService.getBlocks()` executes the resulting query against the database: [5](#0-4) 

**Root cause — failed assumption:** The code assumes `filterValidityChecks` / `isValidTimestampParam` is sufficient to prevent abusive timestamp values. It is not. The utility function `parseTimestampFilters()` — which enforces `maxTimestampRange`, requires both bounds when `allowOpenRange=false`, and can reject open-ended future ranges — is called in `contractController` and `accounts` but is **never invoked** in the blocks controller path. [6](#0-5) 

**Why existing checks fail:**
- `isValidTimestampParam` is purely a regex format check with no semantic bound.
- `buildAndValidateFilters` for blocks uses no custom validator and no `filterDependencyChecker` that would require an upper bound.
- There is no REST-layer rate limiter visible for the `/api/v1/blocks` endpoint (the `ThrottleConfiguration` found is scoped to the separate `web3` Java service). [7](#0-6) 

### Impact Explanation
Each request with `timestamp=gte:9999999999` causes PostgreSQL to perform an index scan on `consensus_end` that finds zero matching rows. The query still consumes a connection from the pool for its full round-trip. Under sustained fire (hundreds of requests/second from a single client or a small botnet), the connection pool saturates, causing legitimate requests to queue and eventually time out. This is a denial-of-service against the mirror node REST API with no authentication barrier.

### Likelihood Explanation
The endpoint is public and unauthenticated. The exploit requires only a single HTTP GET with a crafted query parameter — no special knowledge, credentials, or protocol state. It is trivially scriptable (`curl` in a loop or any HTTP load tool). The attacker needs no privileged access whatsoever.

### Recommendation
1. **Reject future timestamps at validation time**: extend `isValidTimestampParam` or add a dedicated block-filter validator that rejects values greater than `now + small_grace_period`.
2. **Require an upper bound or cap the open range**: invoke `parseTimestampFilters()` (with `allowOpenRange=false` or a tight `maxTimestampRange`) in `extractSqlFromBlockFilters`, consistent with how `contractController` handles timestamp filters.
3. **Add REST-layer rate limiting** to the `/api/v1/blocks` route (e.g., via an Express middleware such as `express-rate-limit`).
4. **Short-circuit on empty-range detection**: if the resolved timestamp range is provably empty (lower bound > current chain tip), return an empty response immediately without issuing a DB query.

### Proof of Concept

```bash
# Single request — returns empty blocks, causes one index scan
curl "https://<mirror-node>/api/v1/blocks?timestamp=gte:9999999999"

# DoS loop — saturates DB connection pool
while true; do
  curl -s "https://<mirror-node>/api/v1/blocks?timestamp=gte:9999999999" &
done
```

Preconditions: none — no authentication, no special headers required.
Trigger: `timestamp=gte:9999999999` passes `isValidTimestampParam` (10 digits, valid format), reaches `RecordFileService.getBlocks()`, and executes `SELECT … FROM record_file WHERE consensus_end >= 9999999999000000000 ORDER BY consensus_end DESC LIMIT 25` — an index scan returning 0 rows.
Result: repeated empty scans exhaust the DB connection pool, degrading or denying service to legitimate callers.

### Citations

**File:** rest/controllers/blockController.js (L21-26)
```javascript
const acceptedBlockParameters = new Set([
  filterKeys.BLOCK_NUMBER,
  filterKeys.LIMIT,
  filterKeys.ORDER,
  filterKeys.TIMESTAMP,
]);
```

**File:** rest/controllers/blockController.js (L63-88)
```javascript
  extractSqlFromBlockFilters = (filters) => {
    const filterQuery = {
      order: this.extractOrderFromFilters(filters),
      orderBy: this.extractOrderByFromFilters(filters),
      limit: this.extractLimitFromFilters(filters),
      whereQuery: [],
    };

    if (filters && filters.length === 0) {
      return filterQuery;
    }

    filterQuery.whereQuery = filters
      .filter((f) => blockWhereFilters.includes(f.key))
      .map((f) => {
        switch (f.key) {
          case filterKeys.BLOCK_NUMBER:
            return this.getFilterWhereCondition(RecordFile.INDEX, f);

          case filterKeys.TIMESTAMP:
            return this.getFilterWhereCondition(RecordFile.CONSENSUS_END, f);
        }
      });

    return filterQuery;
  };
```

**File:** rest/controllers/blockController.js (L101-104)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);
```

**File:** rest/utils.js (L151-154)
```javascript
const isValidTimestampParam = (timestamp) => {
  // Accepted forms: seconds or seconds.upto 9 digits
  return /^\d{1,10}$/.test(timestamp) || /^\d{1,10}\.\d{1,9}$/.test(timestamp);
};
```

**File:** rest/utils.js (L362-364)
```javascript
    case constants.filterKeys.TIMESTAMP:
      ret = isValidTimestampParam(val);
      break;
```

**File:** rest/utils.js (L1583-1666)
```javascript
const parseTimestampFilters = (
  filters,
  filterRequired = true,
  allowNe = false,
  allowOpenRange = false,
  strictCheckOverride = true,
  validateRange = true
) => {
  const forceStrictChecks = strictCheckOverride || config.strictTimestampParam;

  if (filters.length === 0) {
    if (filterRequired) {
      throw new InvalidArgumentError('No timestamp range or eq operator provided');
    }

    return {range: null, neValues: [], eqValues: []};
  }

  let earliest = null;
  let latest = null;
  let range = null;
  const eqValues = new Set();
  const neValues = new Set();
  let lowerBoundFilterCount = 0;
  let upperBoundFilterCount = 0;

  for (const filter of filters) {
    let value = BigInt(filter.value);
    switch (filter.operator) {
      case opsMap.eq:
        eqValues.add(value);
        break;
      case opsMap.ne:
        neValues.add(value);
        break;
      case opsMap.gt:
        value += 1n;
      case opsMap.gte:
        earliest = bigIntMax(earliest ?? 0n, value);
        lowerBoundFilterCount += 1;
        break;
      case opsMap.lt:
        value -= 1n;
      case opsMap.lte:
        latest = bigIntMin(latest ?? constants.MAX_LONG, value);
        upperBoundFilterCount += 1;
        break;
    }
  }

  if (forceStrictChecks) {
    if (!allowNe && neValues.size > 0) {
      throw new InvalidArgumentError('Not equals operator not supported for timestamp param');
    }

    if (lowerBoundFilterCount > 1) {
      throw new InvalidArgumentError('Multiple gt or gte operators not permitted for timestamp param');
    }

    if (upperBoundFilterCount > 1) {
      throw new InvalidArgumentError('Multiple lt or lte operators not permitted for timestamp param');
    }

    if (eqValues.size > 0 && (lowerBoundFilterCount > 0 || upperBoundFilterCount > 0 || neValues.size > 0)) {
      throw new InvalidArgumentError('Cannot combine eq with ne, gt, gte, lt, or lte for timestamp param');
    }
  }

  if (!allowOpenRange && eqValues.size === 0 && (lowerBoundFilterCount === 0 || upperBoundFilterCount === 0)) {
    throw new InvalidArgumentError('Timestamp range must have gt (or gte) and lt (or lte), or eq operator');
  }

  const difference = latest !== null && earliest !== null ? latest - earliest + 1n : null;

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

**File:** rest/service/recordFileService.js (L149-162)
```javascript
  async getBlocks(filters) {
    const {where, params} = buildWhereSqlStatement(filters.whereQuery);

    const query =
      RecordFileService.blocksQuery +
      `
      ${where}
      order by ${filters.orderBy} ${filters.order}
      limit ${filters.limit}
    `;

    const rows = await super.getRows(query, params);
    return rows.map((recordFile) => new RecordFile(recordFile));
  }
```
