### Title
UNION ALL Subquery Overlap Produces Duplicate Rows When Primary Bound Lower == Upper Value

### Summary
When an unprivileged user supplies `spender.id=gte:N&spender.id=lte:N` (same value for both bounds) together with a secondary `token.id` range, `getLowerFilters()` and `getUpperFilters()` both emit `spender = N` as their primary condition. Because `UNION ALL` (not `UNION`) is used in `getQuery()`, any row satisfying both the lower-subquery token condition and the upper-subquery token condition is returned twice. All existing validation checks fail to catch this degenerate range.

### Finding Description

**Code path:**

- `rest/controllers/tokenAllowanceController.js` → `getAccountTokenAllowances()` (line 68–81) calls `extractTokenMultiUnionQuery()` then `TokenAllowanceService.getAccountTokenAllowances(query)`.
- `rest/controllers/baseController.js` → `getLowerFilters()` (lines 131–146), `getInnerFilters()` (lines 154–168), `getUpperFilters()` (lines 176–183).
- `rest/service/tokenAllowanceService.js` → `getQuery()` (lines 54–78) assembles subqueries with `union all` (line 74).

**Root cause — degenerate range `gte:N & lte:N`:**

With query params `spender.id=gte:5&spender.id=lte:5&token.id=gte:10&token.id=lte:20`:

```
primary.lower  = { operator: '>=', value: 5 }
primary.upper  = { operator: '<=', value: 5 }
secondary.lower = { operator: '>=', value: 10 }
secondary.upper = { operator: '<=', value: 20 }
```

`getLowerFilters` branch `primary.hasLower() && secondary.hasLower()` fires:
```js
filters = [{...primary.lower, operator: eq}, secondary.lower]
// → spender = 5  AND  token_id >= 10
``` [1](#0-0) 

`getUpperFilters` fires because both `primary.hasUpper()` and `secondary.hasUpper()`:
```js
return [{...primary.upper, operator: eq}, secondary.upper]
// → spender = 5  AND  token_id <= 20
``` [2](#0-1) 

`getInnerFilters` emits `spender > 5 AND spender < 5` — logically impossible, returns zero rows but is still a non-empty filter array, so all three subqueries are included. [3](#0-2) 

The assembled SQL (line 74) is:
```sql
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=5 AND token_id>=10 ORDER BY ... LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender>5 AND spender<5 ORDER BY ... LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=$1 AND amount>0 AND spender=5 AND token_id<=20 ORDER BY ... LIMIT $2)
ORDER BY spender ASC, token_id ASC LIMIT $2
``` [4](#0-3) 

Any row `(spender=5, token_id=15)` satisfies both subquery 1 (`token_id >= 10`) and subquery 3 (`token_id <= 20`), so it appears **twice** in the `UNION ALL` result.

**Why existing validation is insufficient:**

`validateBoundsRange` only rejects the combination of a range filter **and** an equal filter on the same key. A pure `gte + lte` range (no `eq`) passes silently. [5](#0-4) 

`validateLowerBounds` only rejects `gt` (strict) without a matching primary lower; `gte` passes. [6](#0-5) 

`validateUpperBounds` only rejects `lt` (strict) without a matching primary upper; `lte` passes. [7](#0-6) 

None of the validators check whether `primary.lower.value == primary.upper.value`.

### Impact Explanation
The API endpoint `GET /accounts/{id}/allowances/tokens` returns duplicate allowance rows to any caller. Clients that sum or display allowances will see inflated values. Additionally, because each subquery has its own `LIMIT $2` and the outer query also has `LIMIT $2`, duplicates consume result slots and can suppress real allowance rows that should appear within the page, causing data to be silently omitted from subsequent pages. Severity: **Medium** (data integrity / incorrect read; no write or fund-loss path, but directly misleads consumers of the API).

### Likelihood Explanation
No authentication or privilege is required — the endpoint is public read-only. The trigger is a single crafted HTTP request with two query parameters set to the same numeric value. It is trivially repeatable and requires no special knowledge beyond reading the API documentation. Any automated client or attacker can reproduce it deterministically.

### Recommendation
Add a validation step in `validateBounds` (or inside `validateBoundsRange`) that rejects the degenerate case where `primary.lower.value === primary.upper.value` when both are range operators (`gte`/`lte`). Alternatively, after computing lower/inner/upper filters, detect that the lower and upper subqueries share the same primary equality value and merge them into a single subquery with a combined token-id range condition (`token_id >= A AND token_id <= B`) instead of emitting two separate subqueries joined by `UNION ALL`.

### Proof of Concept

**Precondition:** At least one token allowance row exists for owner account `1001`, spender `5`, with `token_id` between 10 and 20 (e.g., `token_id = 15`), and `amount > 0`.

**Request:**
```
GET /api/v1/accounts/1001/allowances/tokens?spender.id=gte:5&spender.id=lte:5&token.id=gte:10&token.id=lte:20
```

**Generated SQL (simplified):**
```sql
(SELECT * FROM token_allowance WHERE owner=1001 AND amount>0 AND spender=5 AND token_id>=10 ORDER BY spender ASC, token_id ASC LIMIT 25)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=1001 AND amount>0 AND spender>5 AND spender<5 ORDER BY spender ASC, token_id ASC LIMIT 25)
UNION ALL
(SELECT * FROM token_allowance WHERE owner=1001 AND amount>0 AND spender=5 AND token_id<=20 ORDER BY spender ASC, token_id ASC LIMIT 25)
ORDER BY spender ASC, token_id ASC LIMIT 25;
```

**Result:** The row `(owner=1001, spender=5, token_id=15, amount=X)` appears **twice** in the JSON `allowances` array. No error is returned; the response is HTTP 200 with silently duplicated data.

### Citations

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
