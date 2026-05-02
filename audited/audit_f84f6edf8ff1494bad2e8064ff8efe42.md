Based on my thorough code analysis, I have all the information needed to evaluate this.

### Title
Silent HTTP 200 Empty Response for Inverted Timestamp Range in `/api/v1/balances`

### Summary
The `/api/v1/balances` endpoint accepts `timestamp=gt:T1&timestamp=lt:T2` where T1 > T2 without any cross-parameter validation. This causes `getOptimizedTimestampRange()` to return `{}`, which propagates through `getAccountBalanceTimestampRange()` and `getTsQuery()` as empty objects, causing `getBalances()` to return HTTP 200 with an empty balances array — indistinguishable from a legitimately empty result set or a DB partition failure.

### Finding Description

**Exact code path:**

`getBalances()` at [1](#0-0)  calls `utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator)`. The `balanceFilterValidator` delegates to `utils.filterValidityChecks(param, op, val)` for TIMESTAMP params: [2](#0-1) 

`filterValidityChecks` for TIMESTAMP only calls `isValidTimestampParam(val)`: [3](#0-2) 

`isValidTimestampParam` validates only the format of each individual timestamp value: [4](#0-3) 

There is **no cross-parameter validation** that T1 < T2. The `parseTimestampFilters()` function (which does validate inverted ranges and throws `InvalidArgumentError`) is **not called** in the `getBalances()` flow — it is only used in other endpoints like `getOneAccount`.

After validation passes, `parseTimestampQueryParam` builds the SQL fragment per-param with no ordering check: [5](#0-4) 

Then `getOptimizedTimestampRange()` computes `lowerBound = T1 + 1n` (from `gt`) and `upperBound = T2 - 1n` (from `lt`). When T1 > T2, `lowerBound > upperBound` and it returns `{}`: [6](#0-5) 

`getAccountBalanceTimestampRange()` destructures `lowerBound` from `{}`, gets `undefined`, and returns `{}`: [7](#0-6) 

`getTsQuery()` destructures `lower` from `{}`, gets `undefined`, and returns `{}`: [8](#0-7) 

`getBalances()` checks `!tsQueryResult.query` (truthy for `{}`), sets `res.locals` to the pre-initialized empty response, and returns: [9](#0-8) 

The response is HTTP 200 with `{timestamp: null, balances: [], links: {next: null}}`.

**Root cause:** The `getBalances()` validation path uses per-value format checks only. The cross-parameter range inversion check present in `parseTimestampFilters()` is absent from this code path. The test suite explicitly encodes this behavior as expected: [10](#0-9) 

### Impact Explanation

An unprivileged external user can craft a request with an impossible timestamp range (T1 > T2) and receive HTTP 200 with an empty `balances` array. This response is **structurally identical** to a legitimate empty result (no accounts in range) or a DB partition failure returning no rows. Monitoring and alerting systems that rely on non-empty balance responses to detect DB health will be unable to distinguish the two cases. Additionally, the caller receives no error signal (no HTTP 400) indicating the query was logically impossible, violating the principle of least surprise and making the API unreliable for health-check purposes.

### Likelihood Explanation

No authentication or special privileges are required. The exploit requires only knowledge of the API's timestamp parameter syntax, which is publicly documented in the OpenAPI spec: [11](#0-10) 

The request is trivially repeatable and automatable. Any user of the public API can trigger this.

### Recommendation

Add cross-parameter timestamp range validation in the `getBalances()` flow, consistent with how `parseTimestampFilters()` handles it elsewhere. Specifically, after parsing the timestamp query params, check whether the effective lower bound exceeds the effective upper bound and throw an `InvalidArgumentError` (HTTP 400) rather than silently returning empty results. Alternatively, refactor `getBalances()` to use `parseTimestampFilters()` for its timestamp parsing, which already performs this check: [12](#0-11) 

### Proof of Concept

```
GET /api/v1/balances?timestamp=gt:2000000000&timestamp=lt:1000000000
```

**Preconditions:** None. No authentication required.

**Steps:**
1. Send the above request to a running mirror node REST API.
2. Observe HTTP 200 response: `{"timestamp":null,"balances":[],"links":{"next":null}}`
3. Send the same request with a valid range (e.g., `timestamp=gt:1000000000&timestamp=lt:2000000000`) against a DB with data — also returns HTTP 200 with results.
4. Send the inverted-range request against a DB with a partition failure — also returns HTTP 200 with empty results.

**Result:** Steps 2, 3 (empty DB), and 4 (partition failure) are indistinguishable from the caller's perspective. No HTTP 400 is returned for the logically impossible range.

### Citations

**File:** rest/balances.js (L84-84)
```javascript
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);
```

**File:** rest/balances.js (L102-117)
```javascript
  res.locals[constants.responseDataLabel] = {
    timestamp: null,
    balances: [],
    links: {
      next: null,
    },
  };

  let sqlQuery;
  let sqlParams;

  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }
```

**File:** rest/balances.js (L168-171)
```javascript
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

**File:** rest/balances.js (L279-282)
```javascript
  const {lower, upper} = await getAccountBalanceTimestampRange(tsQuery, tsParams);
  if (lower === undefined) {
    return {};
  }
```

**File:** rest/balances.js (L359-363)
```javascript
const balanceFilterValidator = (param, op, val) => {
  return param === constants.filterKeys.ACCOUNT_ID
    ? utils.validateOpAndValue(op, val)
    : utils.filterValidityChecks(param, op, val);
};
```

**File:** rest/utils.js (L151-154)
```javascript
const isValidTimestampParam = (timestamp) => {
  // Accepted forms: seconds or seconds.upto 9 digits
  return /^\d{1,10}$/.test(timestamp) || /^\d{1,10}\.\d{1,9}$/.test(timestamp);
};
```

**File:** rest/utils.js (L362-363)
```javascript
    case constants.filterKeys.TIMESTAMP:
      ret = isValidTimestampParam(val);
```

**File:** rest/utils.js (L694-700)
```javascript
const parseTimestampQueryParam = (parsedQueryParams, columnName, opOverride = {}) => {
  return parseParams(
    parsedQueryParams[constants.filterKeys.TIMESTAMP],
    (value) => parseTimestampParam(value),
    (op, value) => [`${columnName}${op in opOverride ? opOverride[op] : op}?`, [value]],
    false
  );
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

**File:** rest/__tests__/balances.test.js (L46-46)
```javascript
    {operators: [gt, lt], params: ['2022-10-11Z', '2022-10-10Z'], expected: {}},
```

**File:** rest/api/v1/openapi.yml (L391-419)
```yaml
  /api/v1/balances:
    get:
      summary: List account balances
      description:
        Returns a list of account and token balances on the network. The latest balance information is returned when
        there is no timestamp query parameter, otherwise, the information is retrieved from snapshots with 15-minute
        granularity. This information is limited to at most 50 token balances per account as outlined in HIP-367.
        As such, it's not recommended for general use and we instead recommend using either
        `/api/v1/accounts/{id}/tokens` or `/api/v1/tokens/{id}/balances` to obtain the current token balance information
        and `/api/v1/accounts/{id}` to return the current account balance.
      operationId: getBalances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressQueryParam"
        - $ref: "#/components/parameters/accountBalanceQueryParam"
        - $ref: "#/components/parameters/accountPublicKeyQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParamDesc"
        - $ref: "#/components/parameters/timestampQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/BalancesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - balances
```
