### Title
`requestQueryParser()` merge() Bypasses Per-Key Array Limit via Mixed-Case Key Variants

### Summary
`requestQueryParser()` in `rest/middleware/requestHandler.js` first delegates to `qs.parse()` with `arrayLimit` and `throwOnLimitExceeded: true`, which enforces the per-key repetition limit. However, because `qs` treats `KEY`, `Key`, and `key` as three distinct keys, each passes the per-key limit individually. The subsequent lowercasing loop then calls the unbounded `merge()` helper to combine all case variants into a single array, producing a merged array whose length equals the number of distinct-cased variants × values-per-variant — with no size check at the merge step.

### Finding Description

**Exact code path:**

`rest/middleware/requestHandler.js`, `requestQueryParser()`, lines 38–69.

```
// lines 15-20: qs options — limit enforced per-key by qs
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  throwOnLimitExceeded: true,   // throws only when ONE key exceeds the limit
  ...
};

// lines 53-54: qs sees KEY, Key, kEY as three separate keys — each has 1 value → no throw
const parsedQueryString = qs.parse(queryString, queryOptions);

// lines 57-66: lowercasing loop — all three collapse to "key"
for (const [key, value] of Object.entries(parsedQueryString)) {
  const lowerKey = key.toLowerCase();
  if (lowerKey in caseInsensitiveQueryString) {
    caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue); // ← no size check
  } else {
    caseInsensitiveQueryString[lowerKey] = canonicalValue;
  }
}

// lines 39-51: merge() — unbounded, no length guard
const merge = (current, next) => {
  if (!Array.isArray(current)) { current = [current]; }
  if (Array.isArray(next)) { current.push(...next); }
  else { current.push(next); }
  return current;
};
```

**Root cause:** `qs.parse` enforces `arrayLimit` per syntactically distinct key. Mixed-case variants (`KEY`, `Key`, `kEY`) are syntactically distinct to `qs`, so each passes the limit. The post-parse lowercasing merge has no corresponding size guard.

**Why the downstream check is insufficient:** `buildFilters()` in `rest/utils.js` (lines 1241–1248) calls `isRepeatedQueryParameterValidLength(values)` and rejects oversized arrays with a 400. However, this check runs *after* `requestQueryParser` has already allocated the merged array in memory. Every request causes the allocation before the rejection, making it usable for repeated memory-pressure attacks. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) 

### Impact Explanation

An unauthenticated attacker can craft a single HTTP request whose query string contains many mixed-case variants of the same parameter name (e.g., `account.id` has 9 alpha characters → up to 2⁹ = 512 distinct-cased variants). Each variant carries up to `maxRepeatedQueryParameters` values without triggering `qs`'s throw. The merged array can therefore reach `512 × maxRepeatedQueryParameters` entries. Repeated concurrent requests cause repeated heap allocations before the 400 response is sent, creating memory pressure and potential service degradation. No authentication is required. The impact is bounded by HTTP URL length limits (typically 8–16 KB), limiting practical array sizes to hundreds to low thousands of entries per request, placing this squarely in the griefing/DoS tier with no economic damage to network users. [5](#0-4) 

### Likelihood Explanation

Any external user can send HTTP GET requests with no credentials. The attack requires only knowledge of a multi-character parameter name and the ability to enumerate case variants — trivially scriptable. It is repeatable at high frequency. The only natural mitigations are upstream HTTP URL length limits and rate limiting (if configured), neither of which is enforced by the application itself in this code path. [6](#0-5) 

### Recommendation

Add a size check inside `requestQueryParser()` immediately after the `merge()` call, before returning:

```js
caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue);
if (caseInsensitiveQueryString[lowerKey].length > config.query.maxRepeatedQueryParameters) {
  throw new Error(`Parameter count for '${lowerKey}' exceeds maximum allowed`);
}
```

This mirrors the intent of `throwOnLimitExceeded: true` in `qs` but applies it to the post-lowercasing merged result, closing the gap between the `qs`-level check and the downstream `buildFilters` check. [7](#0-6) 

### Proof of Concept

```
# Assuming maxRepeatedQueryParameters = 100, target key "account.id" (9 alpha chars)
# Generate 200 distinct-cased variants of "account.id", each with 1 value:

GET /api/v1/transactions?account.id=1&Account.id=2&aCcount.id=3&acCount.id=4&...
    &ACCOUNT.ID=200
```

1. `qs.parse` sees 200 syntactically distinct keys, each with 1 value → no `throwOnLimitExceeded` trigger.
2. The lowercasing loop merges all 200 into `caseInsensitiveQueryString['account.id']` — a 200-element array.
3. `buildFilters` eventually rejects with HTTP 400, but the 200-element array was already allocated.
4. Repeat concurrently from multiple connections to amplify memory pressure. [8](#0-7) [2](#0-1)

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

**File:** rest/utils.js (L1240-1248)
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
```

**File:** rest/__tests__/requestHandler.test.js (L21-38)
```javascript
  test('requestQueryParser for repeated query params of different cases', () => {
    const val = requestQueryParser('transactiontype=bar&transactionType=xyz');
    expect(val).toStrictEqual({transactiontype: ['bar', 'xyz']});
  });

  test('requestQueryParser for repeated query params of different cases with matching repetitions', () => {
    const val = requestQueryParser('transactiontype=bar&transactionType=xyz&transactionType=ppp');
    expect(val).toStrictEqual({transactiontype: ['bar', 'xyz', 'ppp']});
  });

  test('requestQueryParser for repeated query params of different cases with matching repetitions of account and token ids', () => {
    const val = requestQueryParser(
      'account.id=1&token.id=2&account.Id=lt:3&token.Id=gt:4&account.Id=lte:5&token.Id=gte:6&account.id=7&token.id=8&account.ID=9&token.ID=10'
    );
    expect(val).toStrictEqual({
      'account.id': ['1', '7', 'lt:3', 'lte:5', '9'],
      'token.id': ['2', '8', 'gt:4', 'gte:6', '10'],
    });
```
