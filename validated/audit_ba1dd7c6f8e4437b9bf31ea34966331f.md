All code references have been verified against the actual source. Here is the result:

---

Audit Report

## Title
Unauthenticated Impossible-Range Query Causes Unnecessary Database Execution in `GET /blocks`

## Summary
Any unauthenticated caller can supply contradictory `block.number` range filters (e.g., `block.number=gt:0&block.number=lt:0`) to `GET /blocks`. The request passes all existing validation, is assembled into a logically impossible SQL predicate, and is executed against the database on every such request. An existing `isEmptyRange()` utility that detects this condition is never invoked in this code path.

## Finding Description
The full code path was verified:

**Step 1 — `getBlocks()`** in `rest/controllers/blockController.js` lines 101–104 calls `utils.buildAndValidateFilters()` and immediately passes the result to `extractSqlFromBlockFilters()` with no range-consistency check in between. [1](#0-0) 

**Step 2 — `buildAndValidateFilters()`** in `rest/utils.js` lines 1208–1226 validates each filter individually (format, operator, value type) and runs `filterDependencyCheck`, but performs no cross-filter range-consistency check. [2](#0-1) 

**Step 3 — `extractSqlFromBlockFilters()`** in `rest/controllers/blockController.js` lines 63–88 iterates every filter matching `blockWhereFilters` and maps each one to a `{query, param}` pair with no range-sanity check. For `block.number=gt:0&block.number=lt:0` this produces `whereQuery: [{query:'index >', param:0}, {query:'index <', param:0}]`. [3](#0-2) 

**Step 4 — `buildWhereSqlStatement()`** in `rest/service/recordFileService.js` lines 8–17 mechanically assembles `WHERE index > $1 AND index < $2` with `params = [0, 0]`. [4](#0-3) 

**Step 5 — `RecordFileService.getBlocks()`** in `rest/service/recordFileService.js` lines 149–162 executes the assembled query unconditionally via `super.getRows(query, params)`. [5](#0-4) 

**Step 6 — `isEmptyRange()`** in `rest/utils.js` lines 901–947 exists and correctly detects that `gt:0` + `lt:0` on the same key produces an empty range (`upper < lower`). [6](#0-5) 

**Step 7 — `isEmptyRange()` is only called** inside `getNextParamQueries()` at line 888 for pagination link generation, and is **never called** during request validation for the `/blocks` endpoint. [7](#0-6) 

## Impact Explanation
Every impossible-range request causes a full round-trip to the PostgreSQL backend. While the planner may short-circuit the scan, the connection is consumed, the query is parsed and planned, and the result is serialized. An attacker sending a high volume of such requests amplifies database connection and CPU load with zero authentication cost. Because the response is always a valid `200 OK` with an empty `blocks` array, the attacker receives no error signal to stop.

## Likelihood Explanation
The exploit requires no credentials, no special knowledge, and no tooling beyond a standard HTTP client. The parameter format (`gt:0`, `lt:0`) is documented in the public API. The attack is trivially scriptable and repeatable at any rate the network allows.

## Recommendation
Call `isEmptyRange()` — already present in `rest/utils.js` — either inside `buildAndValidateFilters()` as a cross-filter range check, or at the top of `extractSqlFromBlockFilters()` before assembling `whereQuery`. If an empty range is detected, return an empty result immediately (or throw an `InvalidArgumentError`) without issuing a database query. This eliminates the unnecessary round-trip at zero cost, since the utility already handles the exact condition described.

## Proof of Concept
```
GET /api/v1/blocks?block.number=gt:0&block.number=lt:0
```
Expected (current) behavior: `200 OK` with `{"blocks":[], "links":{"next":null}}` after a database round-trip executing `WHERE index > $1 AND index < $2` with params `[0, 0]`.

Expected (fixed) behavior: immediate `200 OK` with empty result (or `400 Bad Request`) without any database query.

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

**File:** rest/utils.js (L865-893)
```javascript
const getNextParamQueries = (order, reqQuery, lastValueMap) => {
  const pattern = operatorPatterns[order];
  const newPattern = order === constants.orderFilterValues.ASC ? 'gt' : 'lt';

  let firstField = null;
  let primaryField = null;
  for (const [field, lastValue] of Object.entries(lastValueMap)) {
    let value = lastValue;
    let inclusive = false;
    if (typeof value === 'object' && 'value' in lastValue) {
      value = lastValue.value;
      inclusive = lastValue.inclusive;
    }
    const insertValue = inclusive ? `${newPattern}e:${value}` : `${newPattern}:${value}`;
    updateReqQuery(reqQuery, field, pattern, insertValue);

    firstField = firstField ?? field;
    if (lastValue.primary) {
      primaryField = field;
    }
  }

  primaryField = primaryField ?? firstField;
  if (isEmptyRange(primaryField, reqQuery[primaryField])) {
    return null;
  }

  return constructStringFromUrlQuery(reqQuery);
};
```

**File:** rest/utils.js (L901-947)
```javascript
const isEmptyRange = (key, value) => {
  const values = Array.isArray(value) ? value : [value];
  let lower = null;
  let upper = null;

  for (const v of values) {
    if (!gtLtPattern.test(v)) {
      continue;
    }

    const filter = buildComparatorFilter(key, v);
    formatComparator(filter);

    // formatComparator doesn't handle CONTRACT_ID and SLOT
    if (key === constants.filterKeys.CONTRACT_ID) {
      filter.value = EntityId.parse(filter.value).getEncodedId();
    } else if (key === constants.filterKeys.SLOT) {
      filter.value = addHexPrefix(filter.value);
    }

    if (filter.value == null) {
      continue;
    }

    let parsed = BigInt(filter.value);
    switch (filter.operator) {
      case opsMap.gt:
        parsed += 1n;
      case opsMap.gte:
        lower = lower === null ? parsed : bigIntMax(lower, parsed);
        break;
      case opsMap.lt:
        parsed -= 1n;
      case opsMap.lte:
        upper = upper === null ? parsed : bigIntMin(upper, parsed);
        break;
      default:
        break;
    }
  }

  if (lower === null || upper === null) {
    return false;
  }

  return upper < lower;
};
```

**File:** rest/utils.js (L1208-1226)
```javascript
const buildAndValidateFilters = (
  query,
  acceptedParameters,
  filterValidator = filterValidityChecks,
  filterDependencyChecker = filterDependencyCheck
) => {
  const {badParams, filters} = buildFilters(query);
  const {invalidParams, unknownParams} = validateAndParseFilters(filters, filterValidator, acceptedParameters);
  badParams.push(...invalidParams);
  badParams.push(...unknownParams);
  if (badParams.length > 0) {
    throw InvalidArgumentError.forRequestValidation(badParams);
  }

  if (filterDependencyChecker) {
    filterDependencyChecker(query);
  }

  return filters;
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
