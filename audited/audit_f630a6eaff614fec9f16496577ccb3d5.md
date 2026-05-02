### Title
Unauthenticated `timestamp=ne:` Operator Accepted on `/api/v1/balances`, Enabling Silent Empty 200 Response via Treasury Snapshot Exclusion

### Summary
The `/api/v1/balances` endpoint accepts the `ne` (not-equals) operator for the `timestamp` parameter without restriction, because `filterValidityChecks` for `TIMESTAMP` only validates the value format, not the operator. An unprivileged attacker can combine a narrow timestamp range with `ne:T` to force `getAccountBalanceTimestampRange()` to return zero rows, causing `getBalances()` to silently return `{timestamp: null, balances: [], links: {next: null}}` with HTTP 200 — a response indistinguishable from genuine data absence, which is especially dangerous during a network partition.

### Finding Description

**Validation gap — `filterValidityChecks` for `TIMESTAMP`:**

In `rest/utils.js` lines 362–364, the `TIMESTAMP` case only validates the value format:

```js
case constants.filterKeys.TIMESTAMP:
  ret = isValidTimestampParam(val);
  break;
```

It does **not** restrict the operator. The `ne` operator is present in `queryParamOperators` (evidenced by `basicOperators` at lines 264–266 explicitly filtering it out), so `validateOpAndValue('ne', val)` returns `true`, and `filterValidityChecks('timestamp', 'ne', val)` returns `true`. Other parameters like `BLOCK_NUMBER` and `SLOT` correctly use `basicOperators` to exclude `ne`, but `TIMESTAMP` does not. [1](#0-0) [2](#0-1) 

**`ne` flows into `getOptimizedTimestampRange` and `getAccountBalanceTimestampRange`:**

`getBalances()` calls `parseTimestampQueryParam` (line 90), which does not apply `parseTimestampFilters`'s strict `allowNe` guard. The resulting `tsQuery` string containing `ne` is passed to `getAccountBalanceTimestampRange` → `getOptimizedTimestampRange`, which collects `ne` values into `neParams` (line 255–256): [3](#0-2) [4](#0-3) 

`getAccountBalanceTimestampRange` then appends the exclusion to the treasury account query (lines 177–179):

```js
if (neParams.length) {
  condition += ' and not consensus_timestamp = any ($4)';
  params.push(neParams);
}
``` [5](#0-4) 

**Silent empty 200 path:**

When the treasury account query returns 0 rows, `getAccountBalanceTimestampRange` returns `{}` (line 190–192). `getTsQuery` propagates this as `{}` (line 280–282). Back in `getBalances`, line 115–117:

```js
if (!tsQueryResult.query) {
  return;
}
```

This `return` exits with the pre-initialized `res.locals` value of `{timestamp: null, balances: [], links: {next: null}}` — a 200 OK with empty body, no error, no log distinguishing it from a legitimate empty result. [6](#0-5) [7](#0-6) 

**Exploit trigger — narrow range + ne:**

An attacker sends:
```
GET /api/v1/balances?timestamp=gte:T&timestamp=lte:T&timestamp=ne:T
```
The optimized range becomes `[T, T]` with `neParams = [T]`. The treasury query becomes:
```sql
WHERE account_id = <treasury> AND consensus_timestamp >= T AND consensus_timestamp <= T
  AND NOT consensus_timestamp = ANY (ARRAY[T])
```
This is always unsatisfiable regardless of whether T is a real snapshot, guaranteeing 0 rows and an empty 200 response. No knowledge of actual snapshot timestamps is required.

For the network-partition variant: the attacker first queries `/api/v1/balances` (no filter) to discover the current snapshot timestamp T, then sends `timestamp=ne:T` alone. During a partition where T is the only snapshot in the ~2-month optimized window, this excludes the sole treasury row and produces the same empty 200.

### Impact Explanation

The silent empty 200 response is protocol-level ambiguous: monitoring systems, operators, and downstream consumers cannot distinguish "no balance data exists" from "balance data was excluded by a crafted query." During a network partition — when operators most need accurate balance data to detect the partition — an attacker can suppress all visible balance information, preventing detection. This constitutes an availability/integrity impact on the observability layer of the network. Severity: **Medium-High** (no authentication required, directly affects network health monitoring).

### Likelihood Explanation

Any unauthenticated HTTP client can trigger this. The `gte:T&lte:T&ne:T` variant requires no prior knowledge and always succeeds. The network-partition variant requires one prior API call to discover T. The attack is trivially repeatable and scriptable. No special privileges, credentials, or network position are needed.

### Recommendation

1. **Restrict the `ne` operator for `TIMESTAMP` in `filterValidityChecks`**: change the `TIMESTAMP` case to use `basicOperators` (which already excludes `ne`) for operator validation:
   ```js
   case constants.filterKeys.TIMESTAMP:
     ret = isValidTimestampParam(val) && includes(basicOperators, op);
     break;
   ```
2. **Return a 400 error instead of silent empty 200** when `getAccountBalanceTimestampRange` returns `{}` due to a timestamp filter that produces no matching snapshot — distinguish "no snapshot found for this filter" from "no data exists."
3. Audit all other endpoints that use `filterValidityChecks` for `TIMESTAMP` to confirm they do not inadvertently accept `ne`.

### Proof of Concept

```bash
# Always-empty attack (no prior knowledge needed):
curl "https://<mirror-node>/api/v1/balances?timestamp=gte:1700000000.000000000&timestamp=lte:1700000000.000000000&timestamp=ne:1700000000.000000000"
# Response: HTTP 200 {"timestamp":null,"balances":[],"links":{"next":null}}

# Network-partition variant:
# Step 1: discover current snapshot timestamp T
T=$(curl -s "https://<mirror-node>/api/v1/balances" | jq -r '.timestamp')
# Step 2: exclude it
curl "https://<mirror-node>/api/v1/balances?timestamp=ne:$T"
# Response: HTTP 200 {"timestamp":null,"balances":[],"links":{"next":null}}
# (when T is the only snapshot in the ~2-month optimized window)
```

### Citations

**File:** rest/utils.js (L264-266)
```javascript
const basicOperators = Object.values(constants.queryParamOperators).filter(
  (o) => o !== constants.queryParamOperators.ne
);
```

**File:** rest/utils.js (L362-364)
```javascript
    case constants.filterKeys.TIMESTAMP:
      ret = isValidTimestampParam(val);
      break;
```

**File:** rest/balances.js (L90-92)
```javascript
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

**File:** rest/balances.js (L177-180)
```javascript
  if (neParams.length) {
    condition += ' and not consensus_timestamp = any ($4)';
    params.push(neParams);
  }
```

**File:** rest/balances.js (L255-257)
```javascript
      } else if (query.includes(utils.opsMap.ne)) {
        neParams.push(value);
      }
```
