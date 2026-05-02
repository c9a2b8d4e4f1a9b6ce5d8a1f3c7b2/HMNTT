### Title
Redundant Timestamp Predicate Injection via Blocks Endpoint Bypasses Strict Filter Checks

### Summary
The `/api/v1/blocks` endpoint processes timestamp filters through `extractSqlFromBlockFilters()` without calling `parseTimestampFilters()`, which is the only function that rejects multiple same-operator timestamp parameters. An unauthenticated attacker can submit exactly 100 identical `timestamp=gte:0` parameters (the maximum allowed by `maxRepeatedQueryParameters`), causing `buildWhereSqlStatement()` in `recordFileService.js` to emit a WHERE clause with 100 redundant `consensus_end >= $N` conditions, all bound to the same value. This forces the PostgreSQL query planner to evaluate a pathologically large predicate list on every such request.

### Finding Description

**Full code path:**

1. `getBlocks` in `rest/controllers/blockController.js` (line 102) calls `utils.buildAndValidateFilters(req.query, acceptedBlockParameters)`. Inside `buildFilters` (`rest/utils.js` line 1241), the only per-key cardinality check is `isRepeatedQueryParameterValidLength`, which enforces `values.length <= config.query.maxRepeatedQueryParameters` (default **100**). Exactly 100 identical `timestamp=gte:0` values satisfies `≤ 100` and passes.

2. `extractSqlFromBlockFilters()` (`rest/controllers/blockController.js` lines 75–85) maps **every** filter whose key is in `blockWhereFilters` to a WHERE condition via `getFilterWhereCondition`. There is no call to `parseTimestampFilters()` and no deduplication. 100 identical `{key:'timestamp', operator:'>=', value:'0'}` filters produce 100 identical entries: `{query: 'consensus_end >=', param: '0000000000'}`.

3. `buildWhereSqlStatement()` in `rest/service/recordFileService.js` (lines 8–16) iterates over the entire `whereQuery` array and emits:
   ```sql
   where consensus_end >= $1 and consensus_end >= $2 and ... and consensus_end >= $100
   ```
   with all 100 parameters bound to `0`. This query is sent to PostgreSQL on every such request.

**Root cause / failed assumption:** The blocks endpoint assumes `buildAndValidateFilters` is sufficient to prevent abusive timestamp repetition. It is not — `buildAndValidateFilters` only enforces a count ceiling (≤ 100), not semantic deduplication. The strict operator-count check that would reject this (`lowerBoundFilterCount > 1` → `"Multiple gt or gte operators not permitted"`) lives exclusively in `parseTimestampFilters()` (`rest/utils.js` lines 1638–1640), which is **never called** in the blocks endpoint flow.

**Why existing checks are insufficient:**
- `isRepeatedQueryParameterValidLength` (`rest/utils.js` line 488): allows up to and including 100 — the attacker uses exactly 100.
- `parseTimestampFilters` (`rest/utils.js` lines 1638–1643): would reject this, but is not invoked by `blockController.js`.
- `buildWhereSqlStatement` in `recordFileService.js` (lines 8–16): performs no deduplication; blindly iterates the full array.

### Impact Explanation
Each malicious request causes PostgreSQL to receive and plan a query with 100 redundant range predicates on an indexed column. While modern PostgreSQL can optimize simple redundant conditions, the planning overhead scales with predicate count and is non-trivial under concurrent load. An attacker sending a sustained stream of such requests (no authentication required, no rate limiting in the code path) can elevate DB CPU usage, degrade query planning for legitimate traffic, and potentially exhaust connection pool resources. The impact is a non-network-based DoS against the database tier.

### Likelihood Explanation
The attack requires zero privileges — the `/api/v1/blocks` endpoint is public. The payload is trivially constructed (a URL with 100 repeated query parameters). It is fully repeatable and can be parallelized across multiple connections. No special knowledge of the system internals is required beyond knowing the endpoint accepts `timestamp` as a query parameter.

### Recommendation
1. **Deduplicate or reject redundant same-operator timestamp filters** in `extractSqlFromBlockFilters()` before building the WHERE array, or call `parseTimestampFilters()` (with `allowOpenRange: true`) to enforce the existing "multiple gt/gte not permitted" invariant.
2. **Reduce the effective ceiling for timestamp parameters** on the blocks endpoint to 2 (one lower bound, one upper bound), independent of the global `maxRepeatedQueryParameters`.
3. **Add deduplication in `buildWhereSqlStatement`** (`recordFileService.js`) as a defense-in-depth measure.

### Proof of Concept

```bash
# Build a query string with 100 identical timestamp=gte:0 parameters
PARAMS=$(python3 -c "print('&'.join(['timestamp=gte:0']*100))")

# Send to the blocks endpoint (no authentication required)
curl -s "http://<mirror-node-host>:5551/api/v1/blocks?${PARAMS}"
```

**Expected result:** The request passes all validation checks and reaches PostgreSQL with the query:
```sql
SELECT ... FROM record_file
WHERE consensus_end >= $1
  AND consensus_end >= $2
  ...
  AND consensus_end >= $100
ORDER BY consensus_end desc
LIMIT 25
```
All 100 `$N` parameters are bound to `0`. Repeating this request in a tight loop from multiple clients causes measurable DB CPU elevation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** rest/service/recordFileService.js (L8-17)
```javascript
const buildWhereSqlStatement = (whereQuery) => {
  let where = '';
  const params = [];
  for (let i = 1; i <= whereQuery.length; i++) {
    where += `${i === 1 ? 'where' : 'and'} ${whereQuery[i - 1].query} $${i} `;
    params.push(whereQuery[i - 1].param);
  }

  return {where, params};
};
```

**File:** rest/utils.js (L488-488)
```javascript
const isRepeatedQueryParameterValidLength = (values) => values.length <= config.query.maxRepeatedQueryParameters;
```

**File:** rest/utils.js (L1638-1643)
```javascript
    if (lowerBoundFilterCount > 1) {
      throw new InvalidArgumentError('Multiple gt or gte operators not permitted for timestamp param');
    }

    if (upperBoundFilterCount > 1) {
      throw new InvalidArgumentError('Multiple lt or lte operators not permitted for timestamp param');
```
