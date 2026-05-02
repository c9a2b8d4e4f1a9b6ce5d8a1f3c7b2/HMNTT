### Title
Unauthenticated DoS via Bracket-Notation Query Parameters Bypassing String Type Assumption in `buildComparatorFilter`

### Summary
The `qs` parser is configured with `depth: 1` in `requestHandler.js`, which allows one level of bracket-notation nesting (e.g., `timestamp[gte]=1` → `{ timestamp: { gte: '1' } }`). This nested object flows unchecked into `buildComparatorFilter()` in `utils.js`, which unconditionally calls `.split(':')` on the value, throwing a `TypeError` when the value is a plain object rather than a string. The error handler maps this unrecognized exception to HTTP 500, enabling any unauthenticated caller to crash any endpoint that processes timestamp (or similar) filters.

### Finding Description

**Root cause chain:**

**Step 1 — Parser allows depth-1 nesting.** [1](#0-0) 

`depth: 1` permits one bracket level. `strictDepth: true` only throws when depth is *exceeded* (> 1), so `timestamp[gte]=1` is within the limit and parses to `{ timestamp: { gte: '1' } }`.

**Step 2 — `requestQueryParser` passes the object through unchanged.** [2](#0-1) 

`canonicalizeValue` returns the object as-is because `timestamp` is not in `queryCanonicalizationMap`. The resulting `req.query` contains `{ timestamp: { gte: '1' } }`.

**Step 3 — `buildFilters` does not guard against plain-object values.** [3](#0-2) 

The only branch taken for a non-array value is the `else` path, which passes the object directly to `buildComparatorFilter`.

**Step 4 — `buildComparatorFilter` crashes on a non-string.** [4](#0-3) 

`filter.split(':')` throws `TypeError: filter.split is not a function` when `filter` is `{ gte: '1' }`.

**Step 5 — Error handler returns HTTP 500.** [5](#0-4) 

`TypeError` matches none of the known error classes (`InvalidArgumentError`, `RangeError`, `NotFoundError`, `DbError`, `HttpError`), so `statusCode` defaults to `INTERNAL_ERROR` (500). The same crash occurs in `parseOperatorAndValueFromQueryParam` if the object reaches `parseParams` instead. [6](#0-5) 

### Impact Explanation
Every API endpoint that calls `buildAndValidateFilters` (transactions, accounts, tokens, contracts, etc.) is reachable without authentication and processes `timestamp` or similar parameters. A single malformed request causes an unhandled `TypeError` and a 500 response. Repeated at high rate this constitutes a reliable, zero-cost DoS against the REST API layer. No data is exfiltrated, but service availability is fully compromised for the duration of the attack.

### Likelihood Explanation
The attack requires no credentials, no special tooling, and no knowledge beyond standard HTTP. The bracket-notation syntax (`timestamp[gte]=1`) is well-known from frameworks like Rails and PHP and is trivially discoverable by any attacker fuzzing query parameters. It is repeatable indefinitely and can be automated with a single `curl` command.

### Recommendation
Apply one or both of the following fixes:

1. **Set `depth: 0`** in `queryOptions` so `qs` never produces nested objects from user input:
   ```js
   const queryOptions = {
     arrayLimit: config.query.maxRepeatedQueryParameters,
     depth: 0,          // was 1 — prevents all bracket-notation nesting
     strictDepth: true,
     throwOnLimitExceeded: true,
   };
   ```

2. **Add a type guard in `buildComparatorFilter`** as a defence-in-depth measure:
   ```js
   const buildComparatorFilter = (name, filter) => {
     if (typeof filter !== 'string') {
       throw InvalidArgumentError.forParams([name]);
     }
     const splitVal = filter.split(':');
     ...
   };
   ```

Fix (1) is the primary mitigation; fix (2) prevents the same class of bug from recurring if `depth` is ever raised again.

### Proof of Concept
```bash
# Against any endpoint that accepts a timestamp filter
curl -v "http://<mirror-node-host>/api/v1/transactions?timestamp[gte]=1"

# Expected (vulnerable): HTTP 500
# Expected (fixed):      HTTP 400 Invalid parameter
```

Internally, `qs.parse('timestamp[gte]=1', {depth:1, strictDepth:true})` returns `{ timestamp: { gte: '1' } }`. When this reaches `buildComparatorFilter`, `{ gte: '1' }.split(':')` throws `TypeError: filter.split is not a function`, which the error handler maps to HTTP 500.

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

**File:** rest/middleware/requestHandler.js (L54-68)
```javascript
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

**File:** rest/utils.js (L512-526)
```javascript
const parseOperatorAndValueFromQueryParam = (paramValue) => {
  // Split the op:value into operation and value and create a SQL query string
  const splitItem = paramValue.split(':');
  if (splitItem.length === 1) {
    // No operator specified. Just use "eq:"
    return {op: opsMap.eq, value: splitItem[0]};
  }
  if (splitItem.length === 2) {
    if (!(splitItem[0] in opsMap)) {
      return null;
    }
    return {op: opsMap[splitItem[0]], value: splitItem[1]};
  }
  return null;
};
```

**File:** rest/utils.js (L1238-1256)
```javascript
  for (const [key, values] of Object.entries(query)) {
    // for repeated params val will be an array
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

**File:** rest/middleware/httpErrorHandler.js (L14-25)
```javascript
const handleError = async (err, req, res, next) => {
  var statusCode = defaultStatusCode;

  if (err instanceof NotFoundError) {
    statusCode = httpStatusCodes.NOT_FOUND;
  } else if (err instanceof InvalidArgumentError || err instanceof RangeError) {
    statusCode = httpStatusCodes.BAD_REQUEST;
  } else if (err instanceof DbError) {
    statusCode = httpStatusCodes.SERVICE_UNAVAILABLE;
  } else if (err instanceof HttpError) {
    statusCode = new StatusCode(err.statusCode, err.msg);
  }
```
