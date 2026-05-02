### Title
`arrayLimit` DoS Protection Bypassed via Mixed-Case Key Merging in `requestQueryParser`

### Summary
The `requestQueryParser` function in `rest/middleware/requestHandler.js` enforces `qs`'s `arrayLimit` (with `throwOnLimitExceeded: true`) per case-sensitive key at parse time, but then lowercases all keys and merges their value arrays in a post-parse loop. An unauthenticated attacker can send the same logical parameter (e.g., `order`) using multiple capitalizations (e.g., `order`, `ORDER`, `Order`, `oRdEr`, …), each group staying under the per-key limit, and have them merged into a single array that is a multiple of `arrayLimit` in size — completely bypassing the intended protection.

### Finding Description

**Exact code path:**

`rest/middleware/requestHandler.js`, lines 15–20 — `queryOptions` configures `qs` with the limit: [1](#0-0) 

`qs.parse` is called with these options at line 54, enforcing the limit **per case-sensitive key**: [2](#0-1) 

The post-parse loop (lines 57–66) lowercases every key and calls `merge()` when the same lowercased key appears more than once: [3](#0-2) 

`merge()` (lines 39–51) unconditionally spreads the next array into the current one with no size check: [4](#0-3) 

`canonicalizeValue` (lines 71–78) then calls `.map()` over the entire merged array for keys in `queryCanonicalizationMap` (`order`, `result`): [5](#0-4) 

**Root cause:** `qs` is case-sensitive; `throwOnLimitExceeded` fires only when a single case-variant of a key exceeds `arrayLimit`. The post-parse merge step has no corresponding size guard, so the final array for a lowercased key can be `K × arrayLimit` elements, where `K` is the number of distinct capitalizations submitted.

**Failed assumption:** The code assumes that enforcing `arrayLimit` at `qs.parse` time is sufficient to bound the size of any value array that downstream code will see. This assumption breaks because the merge step can combine multiple per-key arrays that each individually passed the check.

### Impact Explanation

Any parameter accepted by the API (e.g., `timestamp`, `account.id`, `order`, `result`) can be inflated to an arbitrarily large array. Downstream filter-parsing functions such as `parseParams` in `rest/utils.js` iterate over every element to build SQL `WHERE` clauses and bind-parameter lists: [6](#0-5) 

A single HTTP request carrying, say, 32 capitalizations of `timestamp` (2^5 variants for a 5-character key) each at the `arrayLimit` threshold produces a ~3,200-element array, causing proportionally large SQL construction work and database load. This is a straightforward, zero-authentication, repeatable denial-of-service vector.

### Likelihood Explanation

No authentication or special privilege is required. The attack requires only knowledge of the API's query parameters (publicly documented) and the ability to craft an HTTP request with many repeated parameters using different capitalizations. It is trivially scriptable and repeatable. The number of usable capitalizations grows exponentially with key length, so longer parameter names (e.g., `result`, `account.id`) allow even larger multipliers.

### Recommendation

Add a post-merge size check inside `requestQueryParser` immediately after the `merge()` call (or at the end of the loop), rejecting the request if any merged array exceeds `config.query.maxRepeatedQueryParameters`:

```js
if (Array.isArray(caseInsensitiveQueryString[lowerKey]) &&
    caseInsensitiveQueryString[lowerKey].length > queryOptions.arrayLimit) {
  throw new Error(`Query parameter "${lowerKey}" exceeds the maximum allowed repetitions`);
}
```

Alternatively, enforce the limit inside `merge()` itself so it throws as soon as the combined length would exceed the configured maximum, mirroring the intent of `throwOnLimitExceeded` in `qs`.

### Proof of Concept

Assuming `maxRepeatedQueryParameters` is `N` (e.g., 10), send:

```
GET /api/v1/transactions?order=asc&order=asc&...  (N times, lowercase)
                        &ORDER=asc&ORDER=asc&...  (N times, uppercase)
                        &Order=asc&Order=asc&...  (N times, mixed)
                        ... (repeat for all 2^5 = 32 capitalizations of "order")
HTTP/1.1
```

Each case-variant group has exactly `N` values, so `qs.parse` accepts all of them without throwing. After the post-parse loop, `req.query.order` is an array of `32 × N` elements. For `N = 100`, this yields a 3,200-element array from a single request, with no authentication required.

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

**File:** rest/middleware/requestHandler.js (L39-51)
```javascript
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
```

**File:** rest/middleware/requestHandler.js (L53-54)
```javascript
  // parse first to benefit from qs query handling
  const parsedQueryString = qs.parse(queryString, queryOptions);
```

**File:** rest/middleware/requestHandler.js (L56-66)
```javascript
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

**File:** rest/utils.js (L565-565)
```javascript
const parseParams = (paramValues, processValue, processQuery, allowMultiple) => {
```
