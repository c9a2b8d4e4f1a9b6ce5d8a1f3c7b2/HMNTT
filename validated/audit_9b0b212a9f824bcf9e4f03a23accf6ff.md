Based on my investigation of the actual code, all four required checks pass. Here is my assessment:

---

Audit Report

## Title
Object Injection via Bracket Notation in `requestQueryParser` Causes Unhandled TypeError DoS

## Summary
The `qs` parser is configured with `depth: 1` and `strictDepth: true` in `requestHandler.js`. This combination allows exactly one level of bracket notation (e.g., `result[key]=success`) to parse silently as a plain object `{ key: 'success' }`. The `lowerCaseQueryValue` canonicalization function passes non-string values through unchanged, and `buildComparatorFilter` in `utils.js` unconditionally calls `.split(':')` on the value — throwing a `TypeError` when the value is an object. Any unauthenticated caller can trigger HTTP 500 on any endpoint accepting a `result` or `order` query parameter.

## Finding Description

**Step 1 — Parser allows one level of nesting silently.**

`queryOptions` in `requestHandler.js` sets `depth: 1` and `strictDepth: true`: [1](#0-0) 

With `depth: 1`, `qs.parse('result[key]=success')` produces `{ result: { key: 'success' } }`. The `strictDepth: true` guard only throws a `RangeError` when depth is *exceeded* (i.e., `result[a][b]=x` with `depth: 1`). A single bracket level is within the limit and parses silently.

**Step 2 — `canonicalizeValue` routes the object to `lowerCaseQueryValue`.** [2](#0-1) 

For the key `result`, `queryCanonicalizationMap` maps to `lowerCaseQueryValue`. Since `{ key: 'success' }` is not an `Array`, it is passed directly to `lowerCaseQueryValue`. [3](#0-2) 

**Step 3 — `lowerCaseQueryValue` silently returns the object unchanged.**

The test suite confirms the function's behavior: non-string values are returned as-is (test case `${100} | ${100}`): [4](#0-3) 

So `lowerCaseQueryValue({ key: 'success' })` returns `{ key: 'success' }` unchanged.

**Step 4 — `buildComparatorFilter` crashes with `TypeError`.** [5](#0-4) 

`filter.split(':')` is called unconditionally. When `filter` is `{ key: 'success' }`, this throws `TypeError: filter.split is not a function`.

**Step 5 — `buildFilters` routes non-array values directly to `buildComparatorFilter` with no type guard.** [6](#0-5) 

**Step 6 — The `TypeError` propagates through `buildAndValidateFilters` to Express error middleware, producing HTTP 500.** [7](#0-6) 

`buildAndValidateFilters` calls `buildFilters` synchronously. The `TypeError` is not an `InvalidArgumentError`, so it is not caught and formatted as a 400; it propagates to Express's default error handler as a 500.

## Impact Explanation
Every REST API endpoint that accepts a `result` or `order` query parameter (e.g., `/api/v1/transactions`, `/api/v1/contracts/results`) returns HTTP 500 instead of HTTP 400 for this input. The `queryCanonicalizationMap` explicitly registers both `result` and `order` as targets. [3](#0-2) 

Sustained automated requests cause a flood of 500 responses and associated error-logging overhead, degrading the primary read interface for the Hedera network.

## Likelihood Explanation
No authentication is required. The payload is a standard HTTP query string using bracket notation supported by every HTTP client and browser (e.g., `GET /api/v1/transactions?result[x]=success`). It is trivially repeatable and automatable. The `depth: 1` setting was presumably intended to block deep nesting but inadvertently permits exactly one level — the minimum needed to inject an object for canonicalized keys.

## Recommendation
Apply one or more of the following mitigations:

1. **Set `depth: 0`** in `queryOptions` so bracket notation is never parsed as a nested object — all values remain strings.
2. **Add a type guard in `buildComparatorFilter`**: check `typeof filter === 'string'` before calling `.split(':')`, and throw `InvalidArgumentError` for non-string values.
3. **Add a type guard in `canonicalizeValue`**: reject or stringify non-string, non-array values before passing them downstream.

The most robust fix is option 1 (`depth: 0`), since the API has no legitimate use for nested query objects. [1](#0-0) 

## Proof of Concept

```
GET /api/v1/transactions?result[x]=success HTTP/1.1
Host: <mirror-node-host>
```

**Trace:**
1. `qs.parse('result[x]=success', { depth: 1, strictDepth: true })` → `{ result: { x: 'success' } }`
2. `canonicalizeValue('result', { x: 'success' })` → calls `lowerCaseQueryValue({ x: 'success' })` → returns `{ x: 'success' }`
3. `buildFilters({ result: { x: 'success' } })` → `buildComparatorFilter('result', { x: 'success' })`
4. `{ x: 'success' }.split(':')` → `TypeError: filter.split is not a function`
5. Express error handler returns **HTTP 500**

The same payload works with `order[x]=asc` and on any endpoint that processes these parameters.

### Citations

**File:** rest/middleware/requestHandler.js (L10-13)
```javascript
const queryCanonicalizationMap = {
  order: lowerCaseQueryValue,
  result: lowerCaseQueryValue,
};
```

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
```

**File:** rest/middleware/requestHandler.js (L71-78)
```javascript
const canonicalizeValue = (key, value) => {
  const canonicalizationFunc = queryCanonicalizationMap[key];
  if (canonicalizationFunc === undefined) {
    return value;
  }

  return Array.isArray(value) ? value.map((v) => canonicalizationFunc(v)) : canonicalizationFunc(value);
};
```

**File:** rest/__tests__/utils.test.js (L2182-2192)
```javascript
describe('lowerCaseQueryValue', () => {
  test.each`
    input        | expected
    ${'success'} | ${'success'}
    ${'SUCCESS'} | ${'success'}
    ${'SUCCess'} | ${'success'}
    ${100}       | ${100}
  `('$input', ({input, expected}) => {
    expect(utils.lowerCaseQueryValue(input)).toEqual(expected);
  });
});
```

**File:** rest/utils.js (L1208-1227)
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
};
```

**File:** rest/utils.js (L1254-1256)
```javascript
    } else {
      filters.push(buildComparatorFilter(key, values));
    }
```

**File:** rest/utils.js (L1262-1272)
```javascript
const buildComparatorFilter = (name, filter) => {
  const splitVal = filter.split(':');
  const value = splitVal.pop();
  const operator = splitVal.pop() ?? 'eq';

  return {
    key: name,
    operator,
    value,
  };
};
```
