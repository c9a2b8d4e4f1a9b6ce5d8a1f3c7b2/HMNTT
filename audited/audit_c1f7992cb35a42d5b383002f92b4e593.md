### Title
Unprivileged User Can Silently Suppress Balance Snapshot Results via `timestamp=ne:` Operator in `/api/v1/balances`

### Summary
The `/api/v1/balances` endpoint accepts the `ne` (not-equal) operator for the `timestamp` query parameter because `filterValidityChecks` for `TIMESTAMP` only validates the value format, not the operator. An attacker who knows a snapshot timestamp `Z` can send `timestamp=gte:<X>&timestamp=lte:<Y>&timestamp=ne:<Z>` where `Z` is the only snapshot in `[X,Y]`, causing `getAccountBalanceTimestampRange()` to find zero rows and return `{}`, which propagates as a silent empty response from `getBalances()` — indistinguishable from a genuine data gap.

### Finding Description

**Validation gap — `filterValidityChecks` does not block `ne` for `TIMESTAMP`:**

In `rest/utils.js`, the `filterValidityChecks` function handles `TIMESTAMP` as:

```js
case constants.filterKeys.TIMESTAMP:
  ret = isValidTimestampParam(val);
  break;
``` [1](#0-0) 

This only validates the value format. The operator check at the top of `filterValidityChecks` is:

```js
const validateOpAndValue = (op, val) => {
  return !(op === undefined || val === undefined || !isValidOperatorQuery(op));
};
``` [2](#0-1) 

Since `ne` is a member of `queryParamOperators` (it is only excluded from `basicOperators`, which is not used for `TIMESTAMP`), `isValidOperatorQuery('ne')` returns `true`. The request passes validation. [3](#0-2) 

**Contrast with the Java REST layer**, which explicitly rejects `ne` for timestamp:

```java
if (operator == RangeOperator.NE) {
    throw new IllegalArgumentException(ERROR);
}
``` [4](#0-3) 

The Node.js REST layer has no equivalent guard.

**`parseTimestampFilters` guard is bypassed:** `getBalances()` uses `parseTimestampQueryParam`, not `parseTimestampFilters`. The guard in `parseTimestampFilters` that throws `'Not equals operator not supported for timestamp param'` when `allowNe=false` is never reached for this code path. [5](#0-4) [6](#0-5) 

**`getOptimizedTimestampRange` accepts and propagates `ne`:**

```js
} else if (query.includes(utils.opsMap.ne)) {
  neParams.push(value);
}
``` [7](#0-6) 

**`getAccountBalanceTimestampRange` injects the exclusion into SQL:**

```js
if (neParams.length) {
  condition += ' and not consensus_timestamp = any ($4)';
  params.push(neParams);
}
``` [8](#0-7) 

If `Z` is the only snapshot timestamp for the treasury account in `[lowerBound, upperBound]`, the query returns zero rows. [9](#0-8) 

**Silent empty response propagation:**

```js
if (rows.length === 0) {
  return {};
}
```
→ `getTsQuery` returns `{}` → `!tsQueryResult.query` is truthy → `getBalances` returns early, leaving `res.locals` as `{timestamp: null, balances: [], links: {next: null}}`. [10](#0-9) 

The same `getAccountBalanceTimestampRange` is also called from `accounts.js` (single-account balance lookup) and `tokens.js` (token balances), making those endpoints equally affected. [11](#0-10) 

### Impact Explanation

The attacker causes the API to return `{timestamp: null, balances: [], links: {next: null}}` — the same response as when no balance data exists. There is no error, no warning, and no indication that a `ne` filter suppressed valid data. Any downstream consumer (monitoring dashboard, alerting system, client application) treating this as a genuine data absence will draw incorrect conclusions. During a network partition or incident investigation, this manufactured empty response is indistinguishable from a real data gap, undermining the integrity of balance data availability signals.

### Likelihood Explanation

No privileges are required. The attacker only needs to know a valid snapshot timestamp `Z` in the target range, which is trivially discoverable by first querying the same endpoint without the `ne` filter to observe the returned `timestamp` field. The attack is repeatable, requires a single HTTP request, and leaves no distinguishing trace in the response.

### Recommendation

1. **Block `ne` for `TIMESTAMP` in `filterValidityChecks`** (mirrors the Java layer):
   ```js
   case constants.filterKeys.TIMESTAMP:
     ret = isValidTimestampParam(val) && op !== constants.queryParamOperators.ne;
     break;
   ```
2. **Or route `getBalances` through `parseTimestampFilters`** with `allowNe = false`, consistent with how other endpoints handle timestamp validation.
3. Add an integration test asserting that `GET /api/v1/balances?timestamp=ne:<valid_ts>` returns HTTP 400.

### Proof of Concept

```
# Step 1: Discover a valid snapshot timestamp
GET /api/v1/balances?timestamp=lte:1700000000.000000000&limit=1
# Response includes: "timestamp": "1699950000.123456789"  ← this is Z

# Step 2: Craft the suppression request
GET /api/v1/balances?timestamp=gte:1699900000.000000000
                    &timestamp=lte:1700000000.000000000
                    &timestamp=ne:1699950000.123456789

# Expected (correct) behavior: HTTP 400 – ne operator not supported
# Actual behavior: HTTP 200 with body:
{
  "timestamp": null,
  "balances": [],
  "links": { "next": null }
}
```

### Citations

**File:** rest/utils.js (L264-266)
```javascript
const basicOperators = Object.values(constants.queryParamOperators).filter(
  (o) => o !== constants.queryParamOperators.ne
);
```

**File:** rest/utils.js (L274-276)
```javascript
const validateOpAndValue = (op, val) => {
  return !(op === undefined || val === undefined || !isValidOperatorQuery(op));
};
```

**File:** rest/utils.js (L362-364)
```javascript
    case constants.filterKeys.TIMESTAMP:
      ret = isValidTimestampParam(val);
      break;
```

**File:** rest/utils.js (L1633-1636)
```javascript
  if (forceStrictChecks) {
    if (!allowNe && neValues.size > 0) {
      throw new InvalidArgumentError('Not equals operator not supported for timestamp param');
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/TimestampParameter.java (L40-42)
```java
        if (operator == RangeOperator.NE) {
            throw new IllegalArgumentException(ERROR);
        }
```

**File:** rest/balances.js (L90-92)
```javascript
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
```

**File:** rest/balances.js (L113-117)
```javascript
  if (tsQuery) {
    const tsQueryResult = await getTsQuery(tsQuery, tsParams);
    if (!tsQueryResult.query) {
      return;
    }
```

**File:** rest/balances.js (L177-180)
```javascript
  if (neParams.length) {
    condition += ' and not consensus_timestamp = any ($4)';
    params.push(neParams);
  }
```

**File:** rest/balances.js (L189-196)
```javascript
  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length === 0) {
    return {};
  }

  const upper = rows[0].consensus_timestamp;
  const lower = utils.getFirstDayOfMonth(upper);
  return {lower, upper};
```

**File:** rest/balances.js (L255-257)
```javascript
      } else if (query.includes(utils.opsMap.ne)) {
        neParams.push(value);
      }
```

**File:** rest/accounts.js (L435-438)
```javascript
    const {lower, upper} = await balances.getAccountBalanceTimestampRange(
      balanceSnapshotTsQuery.replaceAll(opsMap.eq, opsMap.lte),
      balanceSnapshotTsParams
    );
```
