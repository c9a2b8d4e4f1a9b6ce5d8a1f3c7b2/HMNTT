I have verified all code references against the actual source. The technical analysis is accurate. Here is my assessment:

---

Audit Report

## Title
`UNION ALL` Duplicate Rows via Equal-Value `gte`/`lte` Spender Bounds with Token Range

## Summary
When `spender.id=gte:N&spender.id=lte:N` (same value N) is combined with a `token.id` range, all four validation checks in `validateBounds` pass without error. `getLowerFilters` and `getUpperFilters` each emit a `spender = N` subquery with overlapping `token_id` conditions. Because `getQuery` joins them with `UNION ALL`, any row satisfying both conditions is returned twice.

## Finding Description

**Parsing (verified in `bound.js` lines 48–68):**

With `spender.id=gte:5&spender.id=lte:5&token.id=gte:100&token.id=lte:200`:
- `primary.lower = {op: >=, val: 5}`
- `primary.upper = {op: <=, val: 5}`
- `secondary.lower = {op: >=, val: 100}`
- `secondary.upper = {op: <=, val: 200}`

**Validation gap (verified in `baseController.js` lines 117–123):**

`validateBoundsRange` only rejects `hasBound() && hasEqual()`. Since neither bound has an `equal` filter set, all four validators pass:

- `validateBoundsRange`: `primary.hasEqual()=false` → no throw [1](#0-0) 
- `validateLowerBounds`: condition evaluates to `true && true && (false || false)` = false → no throw [2](#0-1) 
- `validateUpperBounds`: condition evaluates to `true && true && (false || false)` = false → no throw [3](#0-2) 
- `validateSecondaryBound`: `primary.isEmpty()=false` → no throw [4](#0-3) 

**Filter construction (verified in `baseController.js`):**

`getLowerFilters`: `primary.hasLower() && secondary.hasLower()` is true → emits `[{op: =, val: 5}, {op: >=, val: 100}]` → `spender = 5 AND token_id >= 100` [5](#0-4) 

`getInnerFilters`: emits `spender > 5 AND spender < 5` — logically impossible, always returns 0 rows [6](#0-5) 

`getUpperFilters`: `primary.hasUpper() && secondary.hasUpper()` is true → emits `[{op: =, val: 5}, {op: <=, val: 200}]` → `spender = 5 AND token_id <= 200` [7](#0-6) 

**UNION ALL assembly (verified in `tokenAllowanceService.js` line 74):**

```sql
(select * from token_allowance where owner=$1 and amount>0 and spender=$3 and token_id>=$4 ...)
union all
(select * from token_allowance where owner=$1 and amount>0 and spender>$5 and spender<$6 ...)  -- always empty
union all
(select * from token_allowance where owner=$1 and amount>0 and spender=$7 and token_id<=$8 ...)
-- params: [owner, limit, 5, 100, 5, 5, 5, 200]
``` [8](#0-7) 

Any row with `spender=5` and `100 ≤ token_id ≤ 200` satisfies both the lower and upper subqueries and is returned twice.

## Impact Explanation

- **Inflated response data:** rows in the overlap range (`spender=N`, `lower_token ≤ token_id ≤ upper_token`) appear twice in `allowances[]`, giving callers a false picture of the account's token allowances.
- **Broken pagination:** `getPaginationLink` uses `rows.length < limit` to detect end-of-results. [9](#0-8)  With duplicates consuming limit slots, the `next` cursor is computed from a wrong last-row position, causing pages to be skipped or repeated.
- No data exfiltration beyond what the caller is already entitled to see, but API response correctness is violated for any account queried this way.

## Likelihood Explanation

- Requires zero privileges — the endpoint is public for any valid account address.
- The crafted query string is trivial: `spender.id=gte:N&spender.id=lte:N&token.id=gte:X&token.id=lte:Y`.
- Fully repeatable and deterministic; no race condition or timing dependency.
- Any automated client or script can trigger it on every paginated request.

## Recommendation

In `validateBoundsRange` (or a new dedicated check), detect the case where `primary.hasLower() && primary.hasUpper() && primary.lower.value === primary.upper.value` and reject it with an `InvalidArgumentError` (e.g., "Use eq operator instead of gte/lte with the same value"). [1](#0-0) 

Alternatively, in `getLowerFilters` / `getUpperFilters`, detect this degenerate case and collapse it into a single equality subquery (equivalent to the `primary.hasEqual()` branch at line 142–144), eliminating the duplicate subquery entirely. [10](#0-9) 

## Proof of Concept

```
GET /api/v1/accounts/0.0.1234/allowances/tokens
    ?spender.id=gte:5&spender.id=lte:5
    &token.id=gte:100&token.id=lte:200
    &limit=25
```

If the account has any token allowances with `spender=5` and `100 ≤ token_id ≤ 200`, each such row appears twice in the `allowances[]` array of the response. The `links.next` cursor is derived from the wrong last-row position, breaking subsequent pagination. [11](#0-10)

### Citations

**File:** rest/controllers/baseController.js (L69-75)
```javascript
  validateSecondaryBound(bounds) {
    if (bounds.primary.isEmpty() && !bounds.secondary.isEmpty()) {
      throw new InvalidArgumentError(
        `${bounds.secondary.filterKey} without a ${bounds.primary.filterKey} parameter filter`
      );
    }
  }
```

**File:** rest/controllers/baseController.js (L83-92)
```javascript
  validateLowerBounds(bounds) {
    const {primary, secondary} = bounds;
    if (
      !primary.hasEqual() &&
      secondary.hasLower() &&
      (!primary.hasLower() || primary.lower.operator === utils.opsMap.gt)
    ) {
      throw new InvalidArgumentError(`${primary.filterKey} must have gte or eq operator`);
    }
  }
```

**File:** rest/controllers/baseController.js (L100-109)
```javascript
  validateUpperBounds(bounds) {
    const {primary, secondary} = bounds;
    if (
      !primary.hasEqual() &&
      secondary.hasUpper() &&
      (!primary.hasUpper() || primary.upper.operator === utils.opsMap.lt)
    ) {
      throw new InvalidArgumentError(`${primary.filterKey} must have lte or eq operator`);
    }
  }
```

**File:** rest/controllers/baseController.js (L117-123)
```javascript
  validateBoundsRange(bounds) {
    Object.keys(bounds).forEach((key) => {
      if (bounds[key].hasBound() && bounds[key].hasEqual()) {
        throw new InvalidArgumentError(`Can't support both range and equal for ${bounds[key].filterKey}`);
      }
    });
  }
```

**File:** rest/controllers/baseController.js (L138-141)
```javascript
    } else if (primary.hasLower() && secondary.hasLower()) {
      // both have lower. If primary has lower and secondary doesn't have lower, the lower bound of primary
      // will go into the inner part.
      filters = [{...primary.lower, operator: utils.opsMap.eq}, secondary.lower];
```

**File:** rest/controllers/baseController.js (L142-144)
```javascript
    } else if (primary.hasEqual()) {
      filters = [primary.equal, primary.lower, primary.upper, secondary.lower, secondary.equal, secondary.upper];
    }
```

**File:** rest/controllers/baseController.js (L160-167)
```javascript
    return [
      // if secondary has lower bound, the primary filter should be > ?
      {filter: primary.lower, newOperator: secondary.hasLower() ? utils.opsMap.gt : null},
      // if secondary has upper bound, the primary filter should be < ?
      {filter: primary.upper, newOperator: secondary.hasUpper() ? utils.opsMap.lt : null},
    ]
      .filter((f) => !isNil(f.filter))
      .map((f) => ({...f.filter, operator: f.newOperator || f.filter.operator}));
```

**File:** rest/controllers/baseController.js (L176-183)
```javascript
  getUpperFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasUpper() || !secondary.hasUpper()) {
      return [];
    }
    // the upper part should always have primary filter = ?
    return [{...primary.upper, operator: utils.opsMap.eq}, secondary.upper];
  }
```

**File:** rest/controllers/baseController.js (L198-198)
```javascript
    const isEnd = rows.length < limit;
```

**File:** rest/service/tokenAllowanceService.js (L63-74)
```javascript
    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) => this.getSubQuery(filters, params, accountIdCondition, limitClause, orderClause));

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = this.getSubQuery([], params, accountIdCondition, limitClause, orderClause);
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
```

**File:** rest/controllers/tokenAllowanceController.js (L72-80)
```javascript
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
```
