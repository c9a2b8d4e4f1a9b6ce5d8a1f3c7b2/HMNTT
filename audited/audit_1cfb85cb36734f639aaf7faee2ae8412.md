Looking at the actual code in both files to validate each step of the claimed vulnerability.

**Step 1 — `requestQueryParser` merge behavior** (`rest/middleware/requestHandler.js`, lines 38–69):

`qs.parse` with `throwOnLimitExceeded: true` and `arrayLimit: config.query.maxRepeatedQueryParameters` guards against repeated same-case keys. However, `order=asc&ORDER=desc` are parsed as **two distinct keys** by `qs` (case-sensitive). The subsequent loop lowercases both to `order`, detects the collision at line 60, and calls `merge()`, producing `['asc', 'desc']`. The `arrayLimit` guard is never triggered.

**Step 2 — `parseLimitAndOrderParams` strict equality check** (`rest/utils.js`, lines 669–671):

```js
const value = req.query[constants.filterKeys.ORDER];
if (value === constants.orderFilterValues.ASC || value === constants.orderFilterValues.DESC) {
  order = value;
}
```

When `value` is `['asc','desc']`, neither strict equality passes. `order` silently stays at `defaultOrder` (DESC). No error is raised.

**Step 3 — Does any upstream validation catch this?**

The `filterValidityChecks` path (used by `validateAndParseFilters`) validates individual filter values, not the array itself. But `parseLimitAndOrderParams` is called **directly** by many endpoints without going through `validateAndParseFilters`, so the array value is never individually validated in those code paths.

All five validation gates pass. Output follows:

---

### Title
Silent Order Parameter Bypass via Mixed-Case Key Collision in `requestQueryParser`

### Summary
Sending `?order=asc&ORDER=desc` causes `requestQueryParser()` to merge the two mixed-case keys into a single array `['asc','desc']` under the lowercased `order` key. `parseLimitAndOrderParams()` in `utils.js` uses strict string equality to check the order value, so the array silently fails both checks and the default sort order (DESC) is applied with no error returned to the caller.

### Finding Description
In `rest/middleware/requestHandler.js` lines 38–69, `requestQueryParser()` first calls `qs.parse(queryString, queryOptions)` where `queryOptions.throwOnLimitExceeded = true` and `arrayLimit = config.query.maxRepeatedQueryParameters`. Because `qs` is case-sensitive, `order=asc` and `ORDER=desc` are parsed as two separate keys and the `arrayLimit` guard is never triggered. The subsequent loop (lines 57–66) lowercases both keys to `order`, detects the collision at line 60, and calls `merge()` (lines 39–51), producing `caseInsensitiveQueryString.order = ['asc','desc']`.

In `rest/utils.js` lines 669–671, `parseLimitAndOrderParams()` reads `req.query['order']` and checks:
```js
if (value === constants.orderFilterValues.ASC || value === constants.orderFilterValues.DESC)
```
An array `['asc','desc']` satisfies neither strict equality. The `order` variable remains at `defaultOrder` (DESC) and no error or warning is emitted. Endpoints that call `parseLimitAndOrderParams()` directly (without routing through `validateAndParseFilters`) are fully exposed; the `filterValidityChecks` path is never reached for these endpoints.

### Impact Explanation
Any endpoint using `parseLimitAndOrderParams()` directly will silently apply default DESC ordering regardless of the user's explicit `order=asc` intent. The response is HTTP 200 with no indication the parameter was ignored. Users relying on ascending order (e.g., paginating from oldest to newest transactions) receive results in the wrong order without any error signal, causing incorrect application behavior or data presentation.

### Likelihood Explanation
Exploitation requires zero privileges — any unauthenticated HTTP client can send the crafted query string. The technique is trivial (two query parameters differing only in case), requires no special tooling, and is fully repeatable. Any user or automated client that constructs URLs with mixed-case parameter names (common in some HTTP frameworks) can trigger this unintentionally.

### Recommendation
In `parseLimitAndOrderParams()` (`rest/utils.js`), handle the case where `value` is an array by either (a) taking the last element (consistent with how `getLimitParamValue` handles array `limit`), or (b) returning a 400 error. Additionally, `requestQueryParser()` should reject or error when `merge()` would produce an array for parameters that are defined as single-value (like `order`), rather than silently merging them. A dedicated allowlist of array-permitted parameters would prevent this class of bypass entirely.

### Proof of Concept
```
GET /api/v1/transactions?order=asc&ORDER=desc HTTP/1.1
Host: <mirror-node-host>
```
1. `qs.parse` sees two keys: `order` → `'asc'`, `ORDER` → `'desc'` (no `arrayLimit` violation).
2. `requestQueryParser` loop merges them: `req.query.order = ['asc', 'desc']`.
3. `parseLimitAndOrderParams`: `['asc','desc'] === 'asc'` → false; `['asc','desc'] === 'desc'` → false.
4. Response returns HTTP 200 with results in DESC order, silently ignoring the user's `order=asc` intent. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
```

**File:** rest/middleware/requestHandler.js (L38-69)
```javascript
const requestQueryParser = (queryString) => {
  const merge = (current, next) => {
    if (!Array.isArray(current)) {
      current = [current];
    }

    if (Array.isArray(next)) {
      current.push(...next);
    } else {
      current.push(next);
    }

    return current;
  };

  // parse first to benefit from qs query handling
  const parsedQueryString = qs.parse(queryString, queryOptions);

  const caseInsensitiveQueryString = {};
  for (const [key, value] of Object.entries(parsedQueryString)) {
    const lowerKey = key.toLowerCase();
    const canonicalValue = canonicalizeValue(lowerKey, value);
    if (lowerKey in caseInsensitiveQueryString) {
      // handle repeated values, merge into an array
      caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue);
    } else {
      caseInsensitiveQueryString[lowerKey] = canonicalValue;
    }
  }

  return caseInsensitiveQueryString;
};
```

**File:** rest/utils.js (L662-674)
```javascript
const parseLimitAndOrderParams = (req, defaultOrder = constants.orderFilterValues.DESC) => {
  // Parse the limit parameter
  const limitQuery = `${constants.filterKeys.LIMIT} ? `;
  const limitValue = getLimitParamValue(req.query[constants.filterKeys.LIMIT]);

  // Parse the order parameters (default: descending)
  let order = defaultOrder;
  const value = req.query[constants.filterKeys.ORDER];
  if (value === constants.orderFilterValues.ASC || value === constants.orderFilterValues.DESC) {
    order = value;
  }

  return buildPgSqlObject(limitQuery, [limitValue], order, limitValue);
```
