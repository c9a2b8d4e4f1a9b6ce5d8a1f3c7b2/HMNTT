After tracing the full code path and verifying every referenced line, the claim is technically accurate. Here is the audit report.

---

## Audit Report

## Title
`UNION ALL` Overlap in `TokenAllowanceService.getQuery()` Produces Duplicate Records When `spender.id` Lower and Upper Bounds Share the Same Value

## Summary
When a caller supplies `spender.id=gte:X&spender.id=lte:X` (identical boundary value X) together with secondary bounds on `token.id` (e.g., `token.id=gt:Y&token.id=lt:W`), the filter-decomposition logic in `getLowerFilters()` and `getUpperFilters()` independently rewrites the primary bound to `spender = X` in both the lower and upper sub-queries. Because `UNION ALL` retains all duplicates and no deduplication is applied post-query, every row satisfying `spender = X AND Y < token_id < W` is returned twice in the API response.

## Finding Description

**Code path:**

`getAccountTokenAllowances` controller handler at [1](#0-0)  calls `extractTokenMultiUnionQuery`, which calls `getLowerFilters`, `getInnerFilters`, and `getUpperFilters` to build the three sub-query filter arrays. [2](#0-1) 

`getQuery()` in `TokenAllowanceService` joins all non-empty sub-query arrays with `UNION ALL` and applies no deduplication: [3](#0-2) 

**Root cause — filter generation with equal lower/upper bounds:**

`getLowerFilters()` at line 138–141: when `primary.hasLower() && secondary.hasLower()`, it rewrites `primary.lower` to `operator: eq`, producing `spender = X AND token_id > Y`. [4](#0-3) 

`getUpperFilters()` at line 182: always rewrites `primary.upper` to `operator: eq`, producing `spender = X AND token_id < W`. [5](#0-4) 

`getInnerFilters()` at lines 162–164: rewrites `primary.lower` to `gt` and `primary.upper` to `lt`, producing `spender > X AND spender < X` — which is vacuously empty when both bounds share value X. [6](#0-5) 

**Resulting sub-queries for `spender.id=gte:5&spender.id=lte:5&token.id=gt:100&token.id=lt:200`:**

| Sub-query | Generated WHERE clause |
|-----------|----------------------|
| lower | `spender = 5 AND token_id > 100` |
| inner | `spender > 5 AND spender < 5` ← always empty |
| upper | `spender = 5 AND token_id < 200` |

Any row with `spender = 5 AND 100 < token_id < 200` satisfies **both** lower and upper, so `UNION ALL` returns it twice.

**Why validation does not block this:**

`validateBoundsRange()` only rejects the combination of a range filter *and* an equality filter on the same key — it does not check whether `primary.lower.value === primary.upper.value`. [7](#0-6) 

`validateLowerBounds()` and `validateUpperBounds()` only enforce that the correct operator type (`gte`/`lte`) is present; they do not compare values across bounds. [8](#0-7) 

The existing test case "spender gte and lte, token gt and lt" uses **different** values (`gte:7`, `lte:16`), so the inner sub-query is non-empty and no overlap occurs — the equal-value edge case is untested. [9](#0-8) [10](#0-9) 

## Impact Explanation
The REST API `/accounts/{id}/allowances/tokens` returns duplicate `TokenAllowanceViewModel` entries for the overlapping rows. Downstream consumers (wallets, indexers, compliance tools) that iterate the response will count the same allowance grant multiple times, producing an inflated view of outstanding approvals. While no funds are moved and no on-chain state is affected, the data integrity of the allowance ledger as presented by the mirror node is compromised for any query matching this pattern. [11](#0-10) 

## Likelihood Explanation
Exploitation requires zero privileges — only a valid account ID in the URL path and crafted query parameters. The parameters `spender.id=gte:X&spender.id=lte:X` are syntactically legal, pass all server-side validation, and are accepted by the filter parser. The attack is trivially repeatable with a single unauthenticated HTTP GET request and requires no knowledge of internal state beyond a target account ID. [12](#0-11) 

## Recommendation
Add a validation step in `validateBounds()` (or a dedicated `validateBoundsValues()` method) that checks whether `primary.lower.value === primary.upper.value` when both are present. If they are equal, either:
1. Reject the request with an `InvalidArgumentError` (e.g., "gte and lte values for `spender.id` must differ"), or
2. Internally rewrite the pair to a single `eq` filter, bypassing the multi-union path entirely.

Additionally, add a test case in `tokenAllowanceController.test.js` covering `spender.id=gte:X&spender.id=lte:X` with the same value X to prevent regression. [13](#0-12) 

## Proof of Concept
```
GET /api/v1/accounts/0.0.1234/allowances/tokens?spender.id=gte:5&spender.id=lte:5&token.id=gt:100&token.id=lt:200
```

The generated SQL (derived from `getQuery()`) is:
```sql
(SELECT * FROM token_allowance
  WHERE owner = $1 AND amount > 0 AND spender = $3 AND token_id > $4
  ORDER BY spender ASC, token_id ASC LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance
  WHERE owner = $1 AND amount > 0 AND spender > $5 AND spender < $6  -- always empty: 5 > 5 AND 5 < 5
  ORDER BY spender ASC, token_id ASC LIMIT $2)
UNION ALL
(SELECT * FROM token_allowance
  WHERE owner = $1 AND amount > 0 AND spender = $7 AND token_id < $8
  ORDER BY spender ASC, token_id ASC LIMIT $2)
ORDER BY spender ASC, token_id ASC LIMIT $2
-- params: [1234, 25, 5, 100, 5, 5, 5, 200]
```

Any row `(owner=1234, spender=5, token_id=150, amount>0)` is returned by both the first and third sub-queries, appearing twice in the final result set. [14](#0-13)

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

**File:** rest/controllers/tokenAllowanceController.js (L68-80)
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
```

**File:** rest/service/tokenAllowanceService.js (L54-78)
```javascript
  getQuery(query) {
    const {lower, inner, upper, order, ownerAccountId, limit} = query;
    const params = [ownerAccountId, limit];
    const accountIdCondition = `${TokenAllowance.OWNER} = $1`;
    const limitClause = super.getLimitQuery(2);
    const orderClause = super.getOrderByQuery(
      ...TokenAllowanceService.orderByColumns.map((column) => OrderSpec.from(column, order))
    );

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

    return {sqlQuery, params};
  }
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

**File:** rest/controllers/baseController.js (L83-109)
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

  /**
   * Validate that the Upper Bounds are valid.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
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

**File:** rest/__tests__/controllers/tokenAllowanceController.test.js (L20-24)
```javascript
const spenderEqFilter = {key: SPENDER_ID, operator: eq, value: 5};
const spenderGtFilter = {key: SPENDER_ID, operator: gt, value: 6};
const spenderGteFilter = {key: SPENDER_ID, operator: gte, value: 7};
const spenderLtFilter = {key: SPENDER_ID, operator: lt, value: 15};
const spenderLteFilter = {key: SPENDER_ID, operator: lte, value: 16};
```

**File:** rest/__tests__/controllers/tokenAllowanceController.test.js (L301-325)
```javascript
      name: 'spender gte and lte, token gt and lt',
      filters: [spenderGteFilter, spenderLteFilter, tokenIdGtFilter, tokenIdLtFilter],
      expected: {
        ...defaultExpected,
        bounds: {
          primary: Bound.create({
            lower: spenderGteFilter,
            upper: spenderLteFilter,
            filterKey: SPENDER_ID,
            viewModelKey: 'spender',
          }),
          secondary: Bound.create({
            lower: tokenIdGtFilter,
            upper: tokenIdLtFilter,
            filterKey: TOKEN_ID,
            viewModelKey: 'token_id',
          }),
        },
        lower: [{...spenderGteFilter, operator: eq}, tokenIdGtFilter],
        inner: [
          {...spenderGteFilter, operator: gt},
          {...spenderLteFilter, operator: lt},
        ],
        upper: [{...spenderLteFilter, operator: eq}, tokenIdLtFilter],
      },
```
