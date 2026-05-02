### Title
Unprivileged `timestamp=ne:<snapshot_ts>` Query Forces Stale Balance Snapshot in `/api/v1/balances`

### Summary
The `/api/v1/balances` endpoint accepts the `ne` (not-equals) operator for the `timestamp` query parameter without restriction, because `filterValidityChecks` for `TIMESTAMP` only validates the value format and not the operator. An unprivileged attacker who knows the nanosecond timestamp of the most recent balance snapshot (publicly visible in any prior API response) can craft `timestamp=ne:<snapshot_ts>` to force `getAccountBalanceTimestampRange()` to skip that snapshot and return the previous month's snapshot, yielding balance data that predates any staking reward payouts credited since then.

### Finding Description

**Code path:**

`getBalances()` → `parseTimestampQueryParam()` → `getTsQuery()` → `getAccountBalanceTimestampRange()` → `getOptimizedTimestampRange()`

**Step 1 — Validation does not block `ne` for timestamp.**

`getBalances()` validates the request via `balanceFilterValidator`:

```javascript
// rest/balances.js:359-363
const balanceFilterValidator = (param, op, val) => {
  return param === constants.filterKeys.ACCOUNT_ID
    ? utils.validateOpAndValue(op, val)
    : utils.filterValidityChecks(param, op, val);
};
```

For `timestamp`, `filterValidityChecks` is called. Its `TIMESTAMP` case is:

```javascript
// rest/utils.js:362-364
case constants.filterKeys.TIMESTAMP:
  ret = isValidTimestampParam(val);
  break;
```

`isValidTimestampParam` only checks the value format (`/^\d{1,10}$/` or `seconds.nanos`). The operator is checked only by `validateOpAndValue`, which accepts `ne` because `isValidOperatorQuery` matches `/^(gte?|lte?|eq|ne)$/`. No code in this path rejects `ne` for timestamp on the `/balances` endpoint. [1](#0-0) [2](#0-1) [3](#0-2) 

**Step 2 — `parseTimestampQueryParam` passes `ne` through.**

```javascript
// rest/balances.js:90-92
let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
  [utils.opsMap.eq]: utils.opsMap.lte,
});
```

The `opOverride` only remaps `eq` → `lte`. The `ne` operator is not overridden, so the resulting `tsQuery` is `"consensus_timestamp != ?"` and `tsParams = [<snapshot_ts_ns>]`. [4](#0-3) [5](#0-4) 

**Step 3 — `getOptimizedTimestampRange` collects the `ne` value.**

```javascript
// rest/balances.js:255-257
} else if (query.includes(utils.opsMap.ne)) {
  neParams.push(value);
}
```

With no `gte`/`lte` bounds supplied, `lowerBound` defaults to `0n` and `upperBound` to `MAX_LONG`. The optimized range becomes `[first_day_of_previous_month, MAX_LONG]`. [6](#0-5) 

**Step 4 — `getAccountBalanceTimestampRange` excludes the targeted snapshot.**

```javascript
// rest/balances.js:175-187
let condition = 'account_id = $1 and consensus_timestamp >= $2 and consensus_timestamp <= $3';
const params = [EntityId.systemEntity.treasuryAccount.getEncodedId(), lowerBound, upperBound];
if (neParams.length) {
  condition += ' and not consensus_timestamp = any ($4)';
  params.push(neParams);
}

const query = `
  select consensus_timestamp
  from account_balance
  where ${condition}
  order by consensus_timestamp desc
  limit 1`;
```

The most recent snapshot matching the attacker-supplied timestamp is excluded. The query returns the next-most-recent snapshot — from the previous month — which predates any staking reward payouts credited after it. [7](#0-6) 

**Step 5 — Stale snapshot propagates to the response.**

`getTsQuery` wraps the returned `{lower, upper}` into the balance query range, and `getBalancesQuery` uses it to fetch `account_balance` rows from the older snapshot. The `timestamp` field in the JSON response reflects the older snapshot time, and balances shown do not include staking rewards credited since then. [8](#0-7) [9](#0-8) 

**Why existing checks fail:**

- `filterValidityChecks` for `TIMESTAMP` does not restrict the operator — only the value format is checked.
- `parseTimestampFilters` (which does enforce `allowNe`) is **not** used by `getBalances`; it uses `parseTimestampQueryParam` instead.
- The `opOverride` in `parseTimestampQueryParam` only remaps `eq`, leaving `ne` unblocked.
- There is no post-parse check that rejects a lone `ne` filter before it reaches `getAccountBalanceTimestampRange`. [10](#0-9) [11](#0-10) 

### Impact Explanation

Any caller of `GET /api/v1/balances?timestamp=ne:<current_snapshot_ts>` receives balance data from the previous monthly snapshot. For accounts that have accrued staking rewards since that older snapshot, the returned `balance` field will be lower than the true on-chain balance, misrepresenting pending reward state. Applications or dashboards that consume this endpoint to display or compute staking reward accruals will show incorrect (understated) figures. No funds are directly at risk since this is a read-only API, but the data integrity guarantee of the endpoint is broken for any consumer that trusts the response.

### Likelihood Explanation

The attack requires zero privileges — any HTTP client can issue the request. The current snapshot timestamp is trivially obtained from any prior unauthenticated call to `/api/v1/balances` (it appears as the top-level `timestamp` field). The exploit is fully deterministic, requires no brute-forcing, and is repeatable on every request. The only precondition is knowing the snapshot timestamp, which is public.

### Recommendation

1. **Reject `ne` for timestamp in `getBalances`**: After calling `parseTimestampQueryParam`, check whether the resulting `tsQuery` contains `opsMap.ne` and throw an `InvalidArgumentError` if so — consistent with how other endpoints handle this.
2. **Alternatively, switch `getBalances` to use `parseTimestampFilters`** with `allowNe = false` (the default), which already enforces this restriction.
3. **Harden `filterValidityChecks` for `TIMESTAMP`**: Restrict the allowed operators to `{eq, lt, lte, gt, gte}` explicitly, mirroring the pattern used for `BLOCK_NUMBER` and `SLOT` (which use `basicOperators`, which excludes `ne`). [12](#0-11) [13](#0-12) 

### Proof of Concept

```
# Step 1: Obtain the current balance snapshot timestamp
curl -s "https://<mirror-node>/api/v1/balances?limit=1" | jq .timestamp
# Example output: "1700000000.123456789"
# Convert to nanoseconds: 1700000000123456789

# Step 2: Exclude that snapshot to force fallback to the previous month's snapshot
curl -s "https://<mirror-node>/api/v1/balances?timestamp=ne:1700000000.123456789"

# Expected result:
# - Response "timestamp" field shows a timestamp from the previous month
# - Account balances reflect the older snapshot, omitting staking rewards
#   credited between the older snapshot and the current one
# - No authentication or special privileges required
```

### Citations

**File:** rest/utils.js (L151-158)
```javascript
const isValidTimestampParam = (timestamp) => {
  // Accepted forms: seconds or seconds.upto 9 digits
  return /^\d{1,10}$/.test(timestamp) || /^\d{1,10}\.\d{1,9}$/.test(timestamp);
};

const isValidOperatorQuery = (query) => {
  return /^(gte?|lte?|eq|ne)$/.test(query);
};
```

**File:** rest/utils.js (L264-266)
```javascript
const basicOperators = Object.values(constants.queryParamOperators).filter(
  (o) => o !== constants.queryParamOperators.ne
);
```

**File:** rest/utils.js (L278-282)
```javascript
const filterValidityChecks = (param, op, val) => {
  if (!validateOpAndValue(op, val)) {
    return false;
  }

```

**File:** rest/utils.js (L302-303)
```javascript
      ret = (isPositiveLong(val, true) || isHexPositiveInt(val, true)) && includes(basicOperators, op);
      break;
```

**File:** rest/utils.js (L362-364)
```javascript
    case constants.filterKeys.TIMESTAMP:
      ret = isValidTimestampParam(val);
      break;
```

**File:** rest/utils.js (L694-701)
```javascript
const parseTimestampQueryParam = (parsedQueryParams, columnName, opOverride = {}) => {
  return parseParams(
    parsedQueryParams[constants.filterKeys.TIMESTAMP],
    (value) => parseTimestampParam(value),
    (op, value) => [`${columnName}${op in opOverride ? opOverride[op] : op}?`, [value]],
    false
  );
};
```

**File:** rest/utils.js (L1583-1591)
```javascript
const parseTimestampFilters = (
  filters,
  filterRequired = true,
  allowNe = false,
  allowOpenRange = false,
  strictCheckOverride = true,
  validateRange = true
) => {
  const forceStrictChecks = strictCheckOverride || config.strictTimestampParam;
```

**File:** rest/balances.js (L83-92)
```javascript
const getBalances = async (req, res) => {
  utils.validateReq(req, acceptedBalancesParameters, balanceFilterValidator);

  // Parse the filter parameters for credit/debit, account-numbers, timestamp and pagination
  const [accountQuery, accountParamsPromise] = parseAccountIdQueryParam(req.query, 'ab.account_id');
  const accountParams = await Promise.all(accountParamsPromise);
  // transform the timestamp=xxxx or timestamp=eq:xxxx query in url to 'timestamp <= xxxx' SQL query condition
  let [tsQuery, tsParams] = utils.parseTimestampQueryParam(req.query, 'consensus_timestamp', {
    [utils.opsMap.eq]: utils.opsMap.lte,
  });
```

**File:** rest/balances.js (L167-197)
```javascript
const getAccountBalanceTimestampRange = async (tsQuery, tsParams) => {
  const {lowerBound, upperBound, neParams} = getOptimizedTimestampRange(tsQuery, tsParams);
  if (lowerBound === undefined) {
    return {};
  }

  // Add the treasury account to the query as it will always be in the balance snapshot and account_id is the first
  // column of the primary key
  let condition = 'account_id = $1 and consensus_timestamp >= $2 and consensus_timestamp <= $3';
  const params = [EntityId.systemEntity.treasuryAccount.getEncodedId(), lowerBound, upperBound];
  if (neParams.length) {
    condition += ' and not consensus_timestamp = any ($4)';
    params.push(neParams);
  }

  const query = `
    select consensus_timestamp
    from account_balance
    where ${condition}
    order by consensus_timestamp desc
    limit 1`;

  const {rows} = await pool.queryQuietly(query, params);
  if (rows.length === 0) {
    return {};
  }

  const upper = rows[0].consensus_timestamp;
  const lower = utils.getFirstDayOfMonth(upper);
  return {lower, upper};
};
```

**File:** rest/balances.js (L199-218)
```javascript
const getBalancesQuery = async (accountQuery, balanceQuery, accountIdsQuery, limitQuery, order, tsQueryResult) => {
  const tokenBalanceSubQuery = getTokenBalanceSubQuery(order, tsQueryResult.query);
  const whereClause = `
      where ${[tsQueryResult.query, accountQuery, accountIdsQuery, balanceQuery].filter(Boolean).join(' and ')}`;
  const {lower, upper} = tsQueryResult.timestampRange;
  // The first upper is for the consensus_timestamp in the select fields, also double the lower and the upper since
  // they are used twice, in the token balance subquery and in the where clause of the main query
  const tsParams = [upper, lower, upper, lower, upper];
  const sqlQuery = `
      select distinct on (account_id)
        ab.account_id,
        ab.balance,
        ?::bigint as consensus_timestamp,
        (${tokenBalanceSubQuery}) as token_balances
      from account_balance ab
      ${whereClause}
      order by ab.account_id ${order}, ab.consensus_timestamp desc
      ${limitQuery}`;
  return [sqlQuery, tsParams];
};
```

**File:** rest/balances.js (L229-276)
```javascript
const getOptimizedTimestampRange = (tsQuery, tsParams) => {
  let lowerBound = 0n;
  const neParams = [];
  let upperBound = constants.MAX_LONG;

  // Find the lower bound and the upper bound from tsParams if present
  tsQuery
    .split('?')
    .filter(Boolean)
    .forEach((query, index) => {
      const value = BigInt(tsParams[index]);
      // eq operator has already been converted to the lte operator
      if (query.includes(utils.opsMap.lte)) {
        // lte operator includes the lt operator, so this clause must before the lt clause
        upperBound = utils.bigIntMin(upperBound, value);
      } else if (query.includes(utils.opsMap.lt)) {
        // Convert lt to lte to simplify query
        const ltValue = value - 1n;
        upperBound = utils.bigIntMin(upperBound, ltValue);
      } else if (query.includes(utils.opsMap.gte)) {
        // gte operator includes the gt operator, so this clause must come before the gt clause
        lowerBound = utils.bigIntMax(lowerBound, value);
      } else if (query.includes(utils.opsMap.gt)) {
        // Convert gt to gte to simplify query
        const gtValue = value + 1n;
        lowerBound = utils.bigIntMax(lowerBound, gtValue);
      } else if (query.includes(utils.opsMap.ne)) {
        neParams.push(value);
      }
    });

  if (lowerBound > upperBound) {
    return {};
  }

  // The optimized range of [lower, upper] should overlap with at most two months, with the exception that when upper
  // is more than 1 month in the future, the range may cover more months. Since the partition maintenance job will
  // create at most one monthly partition ahead, it's unnecessary to adjust the upper bound.
  // With the assumption that the data in db is in sync with the network, in other words, the balance information is
  // update-to-date as of NOW in wall clock, the algorithm below sets lower bound to
  //   max(lowerBound from user, first day of the month before the month min(now, upperBound) is in)
  const nowInNs = utils.nowInNs();
  const effectiveUpperBound = utils.bigIntMin(upperBound, nowInNs);
  const optimalLowerBound = utils.getFirstDayOfMonth(effectiveUpperBound, -1);
  lowerBound = utils.bigIntMax(lowerBound, optimalLowerBound);

  return {lowerBound, upperBound, neParams};
};
```

**File:** rest/balances.js (L278-292)
```javascript
const getTsQuery = async (tsQuery, tsParams) => {
  const {lower, upper} = await getAccountBalanceTimestampRange(tsQuery, tsParams);
  if (lower === undefined) {
    return {};
  }

  const query = 'ab.consensus_timestamp >= ? and ab.consensus_timestamp <= ?';
  return {
    query,
    timestampRange: {
      lower,
      upper,
    },
  };
};
```
