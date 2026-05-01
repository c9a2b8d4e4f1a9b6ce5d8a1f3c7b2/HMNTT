### Title
Silent HTTP 200 Empty Response for Logically Impossible Timestamp Range in `/api/v1/balances`

### Summary
When an unprivileged user submits `timestamp=lte:X&timestamp=gte:Y` where `Y > X` (an impossible range), `getOptimizedTimestampRange` detects `lowerBound > upperBound` and returns `{}`. This propagates through `getAccountBalanceTimestampRange` → `getTsQuery` → `getBalances`, which silently returns HTTP 200 with `{"timestamp":null,"balances":[],"links":{"next":null}}` instead of a 400 Bad Request. No existing validation intercepts the cross-parameter inconsistency before this silent early return.

### Finding Description

**Code path:**

1. `getBalances` (`rest/balances.js:84`) calls `utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator)`. This validates individual parameter format and operator syntax but performs **no cross-parameter consistency check** (i.e., it does not verify that `gte` value ≤ `lte` value). [1](#0-0) 

2. `utils.parseTimestampQueryParam` (`rest/balances.js:90`) likewise parses each timestamp parameter in isolation into SQL fragments — no range sanity check. [2](#0-1) 

3. `res.locals[constants.responseDataLabel]` is pre-populated with an empty-success payload at lines 102–108 **before** any range check occurs. [3](#0-2) 

4. `getOptimizedTimestampRange` (`rest/balances.js:260–262`) detects `lowerBound > upperBound` and returns `{}`. This is confirmed by the unit test at `balances.test.js:46` which explicitly expects `{}` for `gt:'2022-10-11Z'` + `lt:'2022-10-10Z'`. [4](#0-3) [5](#0-4) 

5. `getAccountBalanceTimestampRange` (`rest/balances.js:169–171`) checks `lowerBound === undefined` (true for `{}`) and returns `{}`. [6](#0-5) 

6. `getTsQuery` (`rest/balances.js:280–282`) checks `lower === undefined` (true for `{}`) and returns `{}`. [7](#0-6) 

7. Back in `getBalances`, `!tsQueryResult.query` is `true`, so `return;` is executed at line 116 — the pre-set empty payload is sent with **HTTP 200**. [8](#0-7) 

**Root cause:** `getBalances` uses the legacy `parseTimestampQueryParam` (which has no cross-parameter range validation) instead of `parseTimestampFilters`, which explicitly throws `InvalidArgumentError` when `difference <= 0n` (i.e., lower > upper). [9](#0-8) 

**Contrast with other endpoints:** `contractController.js` uses `parseTimestampFilters` with `validateRange = true` and returns 400 for impossible ranges. The `rest-java` implementation also returns 400 for `timestamp=gt:2&timestamp=lt:1`. [10](#0-9) 

### Impact Explanation

Any client receiving HTTP 200 with `balances: []` cannot distinguish between "no accounts have balances in this range" and "the query itself is logically invalid." Client applications that rely on the API to signal bad input (e.g., monitoring tools, wallets, explorers) will silently treat an erroneous query as a valid empty result, potentially causing incorrect business logic — e.g., falsely concluding that all accounts have zero balance at a given time. The inconsistency with other endpoints in the same API compounds the confusion.

### Likelihood Explanation

Trivially exploitable by any unprivileged user with no authentication, no special knowledge, and no rate-limit bypass required. The request is a standard HTTP GET with two query parameters. It is repeatable at will and requires no prior state.

### Recommendation

Replace the `parseTimestampQueryParam` call in `getBalances` with `parseTimestampFilters` (with `validateRange = false` to preserve the existing open-range behavior, but with cross-parameter consistency enforced), or add an explicit pre-check after parsing that throws `InvalidArgumentError` when the computed lower bound exceeds the upper bound — mirroring the check already present in `parseTimestampFilters` at `rest/utils.js:1661`. [11](#0-10) 

### Proof of Concept

```
GET /api/v1/balances?timestamp=lte:1000000000000&timestamp=gte:9000000000000
```

**Expected (correct) response:** HTTP 400 with `{"_status":{"messages":[{"message":"Invalid timestamp range..."}]}}`

**Actual response:** HTTP 200 with `{"timestamp":null,"balances":[],"links":{"next":null}}`

The impossible range (`gte` value 9000000000000 > `lte` value 1000000000000) is silently accepted and returns an empty success response indistinguishable from a valid query with no matching data.

### Citations

**File:** rest/balances.js (L83-92)
```javascript
const getBalances = async (req, res) => {
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);

  // Parse the filter parameters for credit/debit, account-numbers, timestamp and pagination
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
  // transform the timestamp=xxxx or timestamp=eq:xxxx query in url to 'timestamp <= xxxx' SQL query condition
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
```

**File:** rest/balances.js (L102-108)
```javascript
  res.locals[constants.responseDataLabel] = {
    timestamp: null,
    balances: [],
    links: {
      next: null,
    },
  };
```

**File:** rest/balances.js (L113-117)
```javascript
  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }
```

**File:** rest/balances.js (L167-171)
```javascript
const getAccountBalanceTimestampRange = async (tsQuery, tsParams) => {
  const {lowerBound, upperBound, neParams} = getOptimizedTimestampRange(tsQuery, tsParams);
  if (lowerBound === undefined) {
    return {};
  }
```

**File:** rest/balances.js (L260-262)
```javascript
  if (lowerBound > upperBound) {
    return {};
  }
```

**File:** rest/balances.js (L278-282)
```javascript
const getTsQuery = async (tsQuery, tsParams) => {
  const {lower, upper} = await getAccountBalanceTimestampRange(tsQuery, tsParams);
  if (lower === undefined) {
    return {};
  }
```

**File:** rest/utils.js (L694-701)
```javascript
const parseTimestampQueryParam = (parsedQueryParams, columnName, opOverride = {}) => {
  return parseParams(
    parsedQueryParams[constants.filterKeys.TIMESTAMP],
    (value) => parseTimestampParam(value),
    (op, value) => [`${columnName}${op in opOverride ? opOverride[op] : op}?`, [value]],
    false
  );
};
```

**File:** rest/utils.js (L1655-1665)
```javascript
  const difference = latest !== null && earliest !== null ? latest - earliest + 1n : null;

  if (validateRange) {
    const {maxTimestampRange, maxTimestampRangeNs} = config.query;

    // If difference is null, we want to ignore because we allow open ranges and that is known to be true at this point
    if (difference !== null && (difference > maxTimestampRangeNs || difference <= 0n)) {
      throw new InvalidArgumentError(
        `Timestamp range by the lower and upper bounds must be positive and within ${maxTimestampRange}`
      );
    }
```

**File:** rest/__tests__/balances.test.js (L46-46)
```javascript
    {operators: [gt, lt], params: ['2022-10-11Z', '2022-10-10Z'], expected: {}},
```

**File:** rest/controllers/contractController.js (L384-390)
```javascript
const optimizeTimestampFilters = async (timestampFilters, order) => {
  const filters = [];

  const {range, eqValues, neValues} = utils.parseTimestampFilters(timestampFilters, false, true, true, false, false);
  if (range?.isEmpty()) {
    return {filters};
  }
```
