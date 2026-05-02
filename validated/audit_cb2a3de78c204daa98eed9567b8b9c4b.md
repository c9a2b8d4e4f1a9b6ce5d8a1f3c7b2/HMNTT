All referenced code has been verified against the actual source. The claim is technically accurate. Here is the audit report:

---

Audit Report

## Title
UNION ALL Subquery Overlap Produces Duplicate Rows When Primary Bound Lower == Upper Value

## Summary
When a caller supplies `spender.id=gte:N&spender.id=lte:N` (identical lower and upper bound) alongside a secondary `token.id` range, the multi-union query builder in `tokenAllowanceService.js` emits three subqueries via `UNION ALL`. Because the lower and upper subqueries both pin `spender = N` while covering overlapping `token_id` ranges, any row whose `token_id` falls within the intersection is returned twice. No existing validation rejects this degenerate range.

## Finding Description

**Code path verified:**

`extractTokenMultiUnionQuery` in `tokenAllowanceController.js` calls `getLowerFilters`, `getInnerFilters`, and `getUpperFilters` from `baseController.js`, then passes the result to `TokenAllowanceService.getQuery()`. [1](#0-0) 

With `spender.id=gte:5&spender.id=lte:5&token.id=gte:10&token.id=lte:20`:

- `primary.lower = {operator: '>=', value: 5}`, `primary.upper = {operator: '<=', value: 5}`
- `secondary.lower = {operator: '>=', value: 10}`, `secondary.upper = {operator: '<=', value: 20}`

**`getLowerFilters`** hits the `primary.hasLower() && secondary.hasLower()` branch and returns `[spender=5, token_id>=10]`: [2](#0-1) 

**`getInnerFilters`** returns `[spender>5, spender<5]` — a logically impossible but non-empty array, so it is not filtered out by the `filters.length !== 0` guard in `getQuery`: [3](#0-2) 

**`getUpperFilters`** returns `[spender=5, token_id<=20]`: [4](#0-3) 

All three filter arrays are non-empty, so `getQuery` joins all three subqueries with `union all`: [5](#0-4) 

The resulting SQL is:
```sql
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=5 AND token_id>=10 ORDER BY ... LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender>5 AND spender<5 ORDER BY ... LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=5 AND token_id<=20 ORDER BY ... LIMIT $2)
ORDER BY spender ASC, token_id ASC LIMIT $2
```

Any row `(spender=5, token_id=15)` satisfies both subquery 1 (`token_id >= 10`) and subquery 3 (`token_id <= 20`), so it appears twice.

**Why validation does not catch this:**

`validateBoundsRange` only rejects the combination of a range filter **and** an `eq` filter on the same key. A pure `gte + lte` pair (no `eq`) has `hasEqual() = false` and passes silently: [6](#0-5) 

`validateLowerBounds` only rejects `primary.lower.operator === gt` (strict); `gte` passes: [7](#0-6) 

`validateUpperBounds` only rejects `primary.upper.operator === lt` (strict); `lte` passes: [8](#0-7) 

None of the validators compare `primary.lower.value` against `primary.upper.value`. [9](#0-8) 

## Impact Explanation
`GET /accounts/{id}/allowances/tokens` returns duplicate allowance rows. Clients that aggregate or display allowances will see inflated values. Additionally, because each subquery carries its own `LIMIT $2` and the outer query also applies `LIMIT $2`, duplicates consume result slots and can suppress legitimate rows that should appear within the page, causing silent data omission across pages. Severity: **Medium** (data integrity / incorrect read; no write or fund-loss path, but directly misleads API consumers). [10](#0-9) 

## Likelihood Explanation
No authentication is required — the endpoint is public read-only. The trigger is a single HTTP request with two query parameters set to the same numeric value (e.g., `?spender.id=gte:5&spender.id=lte:5&token.id=gte:10&token.id=lte:20`). It is trivially repeatable, requires no special knowledge beyond reading the API documentation, and can be reproduced deterministically by any automated client. [11](#0-10) 

## Recommendation
Add a degenerate-range check inside `validateBounds` (or as a dedicated `validatePrimaryBoundRange` method) that throws `InvalidArgumentError` when `primary.hasLower() && primary.hasUpper() && primary.lower.value === primary.upper.value`. Alternatively, collapse the degenerate case into a single `eq` filter before the bounds are passed to the filter-building methods, so only one subquery is generated. [9](#0-8) 

## Proof of Concept
```
GET /api/v1/accounts/0.0.100/allowances/tokens
    ?spender.id=gte:5&spender.id=lte:5
    &token.id=gte:10&token.id=lte:20
```

Assuming the database contains a single row `(owner=100, spender=5, token_id=15, amount=50)`:

- Subquery 1 (`spender=5 AND token_id>=10`) returns the row.
- Subquery 2 (`spender>5 AND spender<5`) returns zero rows.
- Subquery 3 (`spender=5 AND token_id<=20`) returns the same row.

The `UNION ALL` result contains the row **twice**, so the API response includes two identical allowance entries for `(spender=5, token_id=15)` instead of one. [5](#0-4)

### Citations

**File:** rest/controllers/tokenAllowanceController.js (L51-59)
```javascript
    return {
      bounds,
      lower: this.getLowerFilters(bounds),
      inner: this.getInnerFilters(bounds),
      upper: this.getUpperFilters(bounds),
      order,
      ownerAccountId,
      limit,
    };
```

**File:** rest/controllers/tokenAllowanceController.js (L68-81)
```javascript
  getAccountTokenAllowances = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedTokenAllowanceParameters);
    const query = this.extractTokenMultiUnionQuery(filters, accountId);
    const tokenAllowances = await TokenAllowanceService.getAccountTokenAllowances(query);
    const allowances = tokenAllowances.map((model) => new TokenAllowanceViewModel(model));

    res.locals[responseDataLabel] = {
      allowances,
      links: {
        next: this.getPaginationLink(req, allowances, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/controllers/baseController.js (L56-61)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
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

**File:** rest/controllers/baseController.js (L176-182)
```javascript
  getUpperFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasUpper() || !secondary.hasUpper()) {
      return [];
    }
    // the upper part should always have primary filter = ?
    return [{...primary.upper, operator: utils.opsMap.eq}, secondary.upper];
```

**File:** rest/service/tokenAllowanceService.js (L63-75)
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
    }
```
