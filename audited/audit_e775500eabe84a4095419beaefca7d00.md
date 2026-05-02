### Title
Silent Empty Result Set via Conflicting `block.number` Range Filters in `getBlocks()`

### Summary
The `getBlocks()` handler in `rest/controllers/blockController.js` accepts multiple `block.number` query parameters with conflicting range operators (e.g., `?block.number=gte:100&block.number=lte:50`). Each filter passes individual validation, both are blindly appended to the SQL WHERE clause via `extractSqlFromBlockFilters()`, producing a logically impossible condition (`index >= 100 AND index <= 50`). The database returns zero rows, and the API responds with HTTP 200 and an empty `blocks` array — no error, no warning.

### Finding Description

**Code path:**

`getBlocks()` (`blockController.js:101-112`) calls `utils.buildAndValidateFilters(req.query, acceptedBlockParameters)` with no custom validator, falling back to the default `filterValidityChecks`.

`filterValidityChecks()` (`utils.js:301-303`) validates each `block.number` filter in isolation:
```js
case constants.filterKeys.BLOCK_NUMBER:
  ret = (isPositiveLong(val, true) || isHexPositiveInt(val, true)) && includes(basicOperators, op);
```
Both `gte:100` and `lte:50` individually satisfy this check — the values are positive longs and both operators are in `basicOperators`.

`filterDependencyCheck()` (`utils.js:402-436`) only rejects the combination of `block.hash` + `block.number`, and requires `block.number` when `transaction.index` is present. It performs **no cross-operator consistency check** on multiple `block.number` values.

`extractSqlFromBlockFilters()` (`blockController.js:75-85`) maps every `block.number` filter entry directly to a WHERE condition with no deduplication or conflict detection:
```js
filterQuery.whereQuery = filters
  .filter((f) => blockWhereFilters.includes(f.key))
  .map((f) => {
    switch (f.key) {
      case filterKeys.BLOCK_NUMBER:
        return this.getFilterWhereCondition(RecordFile.INDEX, f);
```

`buildWhereSqlStatement()` (`recordFileService.js:8-16`) joins all conditions with `AND`:
```js
where += `${i === 1 ? 'where' : 'and'} ${whereQuery[i - 1].query} $${i} `;
```
Result: `WHERE index >= $1 AND index <= $2` with params `[100, 50]` — an unsatisfiable predicate.

`getBlocks()` (`recordFileService.js:149-162`) executes the query, gets zero rows, and returns them. The controller (`blockController.js:106-111`) wraps this as `{blocks: [], links: {next: null}}` with HTTP 200.

**Root cause:** The validation pipeline validates each filter in isolation. There is no cross-filter semantic check to detect that a lower-bound value exceeds an upper-bound value for the same column, making the combined WHERE clause logically impossible.

### Impact Explanation
Any API consumer (smart contract bridge, Ethereum JSON-RPC relay, indexer, or dApp) that queries `/api/v1/blocks?block.number=gte:X&block.number=lte:Y` with `X > Y` receives HTTP 200 with an empty `blocks` array and no indication of error. A client that interprets an empty result as "no blocks exist in this range" will silently malfunction — for example, an Ethereum-compatible relay that uses this endpoint to resolve block ranges for `eth_getLogs` or `eth_getBlockByNumber` range queries could report a false absence of blocks, causing smart contracts or off-chain logic depending on block data to behave incorrectly. No funds are directly at risk, but the silent data corruption of block-range queries is a medium-severity protocol integrity issue.

### Likelihood Explanation
The trigger requires zero privileges — any unauthenticated HTTP client can reproduce it with a single crafted GET request. The conflicting filter combination is syntactically valid and passes all existing validation gates. It is trivially repeatable and requires no special knowledge beyond the public API documentation, which explicitly documents `gte`/`lte` as valid operators for `block.number`. Automated clients or smart contract bridges that construct range queries programmatically are the most realistic victims if they have a logic bug in range construction.

### Recommendation
Add a cross-filter semantic validation step in `extractSqlFromBlockFilters()` (or in `filterDependencyCheck()`) that, after collecting all `block.number` filters, checks whether the combined lower-bound (from `gt`/`gte` operators) exceeds the combined upper-bound (from `lt`/`lte` operators). If so, throw an `InvalidArgumentError` with a descriptive message (e.g., `"block.number range is contradictory: lower bound exceeds upper bound"`). This mirrors the pattern already used for `block.hash` + `block.number` mutual exclusion in `filterDependencyCheck()`. Additionally, consider returning HTTP 400 rather than HTTP 200 with an empty result for any logically impossible filter combination.

### Proof of Concept
```
GET /api/v1/blocks?block.number=gte:100&block.number=lte:50
```

**Step-by-step:**
1. Send the above request to a running mirror node REST API instance that has blocks with indices in the range 16–19 (or any populated range).
2. Observe HTTP 200 response:
   ```json
   {
     "blocks": [],
     "links": { "next": null }
   }
   ```
3. No error is returned despite the range being logically impossible.
4. The generated SQL is equivalent to:
   ```sql
   SELECT ... FROM record_file
   WHERE index >= 100 AND index <= 50
   ORDER BY index desc
   LIMIT 25
   ```
   which always returns zero rows regardless of database contents.
5. A valid non-conflicting query `?block.number=gte:16&block.number=lte:19` returns the expected blocks, confirming the database is populated and the empty result is caused solely by the conflicting filters. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest/controllers/blockController.js (L75-85)
```javascript
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
```

**File:** rest/controllers/blockController.js (L101-104)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);
```

**File:** rest/service/recordFileService.js (L8-16)
```javascript
const buildWhereSqlStatement = (whereQuery) => {
  let where = '';
  const params = [];
  for (let i = 1; i <= whereQuery.length; i++) {
    where += `${i === 1 ? 'where' : 'and'} ${whereQuery[i - 1].query} $${i} `;
    params.push(whereQuery[i - 1].param);
  }

  return {where, params};
```

**File:** rest/utils.js (L301-303)
```javascript
    case constants.filterKeys.BLOCK_NUMBER:
      ret = (isPositiveLong(val, true) || isHexPositiveInt(val, true)) && includes(basicOperators, op);
      break;
```

**File:** rest/utils.js (L402-436)
```javascript
const filterDependencyCheck = (query) => {
  const badParams = [];
  let containsBlockNumber = false;
  let containsBlockHash = false;
  let containsTransactionIndex = false;
  for (const key of Object.keys(query)) {
    if (key === constants.filterKeys.TRANSACTION_INDEX) {
      containsTransactionIndex = true;
    } else if (key === constants.filterKeys.BLOCK_NUMBER) {
      containsBlockNumber = true;
    } else if (key === constants.filterKeys.BLOCK_HASH) {
      containsBlockHash = true;
    }
  }

  if (containsTransactionIndex && !(containsBlockNumber || containsBlockHash)) {
    badParams.push({
      key: constants.filterKeys.TRANSACTION_INDEX,
      error: 'transaction.index requires block.number or block.hash filter to be specified',
      code: 'invalidParamUsage',
    });
  }

  if (containsBlockHash && containsBlockNumber) {
    badParams.push({
      key: constants.filterKeys.BLOCK_HASH,
      error: 'cannot combine block.number and block.hash',
      code: 'invalidParamUsage',
    });
  }

  if (badParams.length) {
    throw InvalidArgumentError.forRequestValidation(badParams);
  }
};
```
