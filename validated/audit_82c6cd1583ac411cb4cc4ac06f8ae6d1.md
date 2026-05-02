I have verified every step of the claimed code path against the actual source. Here is my assessment:

**Step 1 — `queryOptions` configuration:** Confirmed at lines 15–20 of `requestHandler.js`. `depth: 1` and `strictDepth: true` are both set. [1](#0-0) 

**Step 2 — `qs` parsing behavior:** With `depth: 1`, `qs.parse('result[key]=success')` produces `{ result: { key: 'success' } }`. The `strictDepth: true` option only throws a `RangeError` when depth is *exceeded* (i.e., `> 1`). A single bracket level is exactly at the limit and parses silently. This is correct per `qs` library semantics.

**Step 3 — `canonicalizeValue` passes the object to `lowerCaseQueryValue`:** Confirmed. The function checks `Array.isArray(value)` but not `typeof value === 'object'`, so a plain object is passed directly to `lowerCaseQueryValue`. [2](#0-1) 

**Step 4 — `lowerCaseQueryValue` returns the object unchanged:** Confirmed at line 209 of `utils.js`. The `typeof queryValue === 'string'` guard causes non-strings to be returned as-is. [3](#0-2) 

**Step 5 — `buildFilters` routes the object to `buildComparatorFilter`:** Confirmed. The `Array.isArray(values)` check at line 1240 is false for a plain object, so the `else` branch at line 1254–1255 calls `buildComparatorFilter(key, values)` with the object. [4](#0-3) 

**Step 6 — `buildComparatorFilter` crashes:** Confirmed. Line 1263 calls `filter.split(':')` unconditionally with no type guard. Passing a plain object throws `TypeError: filter.split is not a function`. [5](#0-4) 

**Step 7 — `queryCanonicalizationMap` targets `result` and `order`:** Confirmed at lines 10–13. [6](#0-5) 

All six steps in the exploit chain are confirmed by the actual code. The vulnerability is real.

---

# Audit Report

## Title
Object Injection via Bracket Notation in `requestQueryParser` Causes TypeError DoS

## Summary
The `qs` parser is configured with `depth: 1`, which silently parses one level of bracket notation (e.g., `result[key]=success`) as a nested object `{ key: 'success' }`. The `lowerCaseQueryValue` canonicalization function passes non-string values through unchanged, and `buildComparatorFilter` unconditionally calls `.split(':')` on the value, crashing with a `TypeError` when the value is an object. Any unauthenticated request to an endpoint accepting a `result` or `order` query parameter can trigger this.

## Finding Description

**Parsing stage** — `requestHandler.js` configures `qs` with `depth: 1` and `strictDepth: true`: [1](#0-0) 

With `depth: 1`, `qs.parse('result[key]=success')` produces `{ result: { key: 'success' } }`. The `strictDepth: true` option only throws a `RangeError` when depth is **exceeded** (i.e., `> 1`). A single bracket level is within the limit and parses silently.

**Canonicalization stage** — `canonicalizeValue` does not guard against plain objects: [2](#0-1) 

`{ key: 'success' }` is not an `Array`, so `lowerCaseQueryValue({ key: 'success' })` is called directly.

**`lowerCaseQueryValue` passes the object through unchanged:** [3](#0-2) 

`typeof { key: 'success' } !== 'string'` evaluates to `true`, so the object is returned as-is.

**`buildFilters` routes the object to `buildComparatorFilter`:** [7](#0-6) 

`Array.isArray({ key: 'success' })` is `false`, so the `else` branch calls `buildComparatorFilter('result', { key: 'success' })`.

**`buildComparatorFilter` crashes with `TypeError`:** [5](#0-4) 

`filter.split(':')` is called unconditionally with no type guard. Passing a plain object throws `TypeError: filter.split is not a function`.

The `TypeError` propagates through `buildAndValidateFilters` → route handler → Express error middleware, producing an HTTP 500 response.

## Impact Explanation
Every REST API endpoint accepting a `result` or `order` query parameter (e.g., `/api/v1/transactions`, `/api/v1/contracts/results`) returns HTTP 500 for any request using bracket notation on those parameters. The `queryCanonicalizationMap` explicitly registers both `result` and `order` as targets. [6](#0-5) 
The mirror node REST API is the primary read interface for the Hedera network; sustained or repeated triggering of this path degrades all client applications relying on it for transaction status, account queries, and contract results.

## Likelihood Explanation
No authentication or special privileges are required. The payload is a standard HTTP query string using bracket notation supported by every HTTP client and browser. It is trivially repeatable and automatable. The `depth: 1` setting was presumably intended to block deep nesting but inadvertently permits exactly one level — the minimum needed to inject an object for canonicalized keys.

## Recommendation
Apply a type guard in `buildComparatorFilter` to reject non-string `filter` arguments before calling `.split()`:

```js
const buildComparatorFilter = (name, filter) => {
  if (typeof filter !== 'string') {
    throw new InvalidArgumentError(`Invalid value for parameter: ${name}`);
  }
  const splitVal = filter.split(':');
  ...
};
```

Alternatively, add a type check in `canonicalizeValue` or `buildFilters` to reject or stringify plain objects before they reach `buildComparatorFilter`. The root cause is the absence of a type guard at any point in the pipeline between `qs.parse` and `filter.split(':')`.

## Proof of Concept
```
GET /api/v1/transactions?result[key]=success HTTP/1.1
Host: <mirror-node-host>
```

`qs.parse('result[key]=success', { depth: 1, strictDepth: true })` → `{ result: { key: 'success' } }`

`lowerCaseQueryValue({ key: 'success' })` → `{ key: 'success' }` (unchanged)

`buildComparatorFilter('result', { key: 'success' })` → `TypeError: filter.split is not a function`

Response: HTTP 500

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

**File:** rest/utils.js (L209-209)
```javascript
const lowerCaseQueryValue = (queryValue) => (typeof queryValue === 'string' ? queryValue.toLowerCase() : queryValue);
```

**File:** rest/utils.js (L1240-1255)
```javascript
    if (Array.isArray(values)) {
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
      }

      for (const val of values) {
        filters.push(buildComparatorFilter(key, val));
      }
    } else {
      filters.push(buildComparatorFilter(key, values));
```

**File:** rest/utils.js (L1262-1263)
```javascript
const buildComparatorFilter = (name, filter) => {
  const splitVal = filter.split(':');
```
