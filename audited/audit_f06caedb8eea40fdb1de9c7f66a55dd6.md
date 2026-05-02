### Title
Unprivileged User Can Trigger 3x Database Load via Dual-Bound NFT Query (UNION ALL Amplification DoS)

### Summary
The `extractNftMultiUnionQuery()` function in `rest/controllers/accountController.js` accepts simultaneous lower and upper bounds on both `token.id` and `serialnumber` from any unauthenticated user. This causes `getLowerFilters()`, `getInnerFilters()`, and `getUpperFilters()` to each return non-empty filter sets, which `NftService.getQuery()` assembles into three separate `UNION ALL` subqueries per request. The REST API has no per-request rate limiting, making this a reliable 3x database load amplifier available to any caller.

### Finding Description
**Code path:**

In `rest/controllers/accountController.js` lines 34–82, `extractNftMultiUnionQuery()` parses filters into a `primary` (`token_id`) and `secondary` (`serial_number`) `Bound` object, then calls `validateFilters()` → `validateBounds()`, then calls `getLowerFilters()`, `getInnerFilters()`, and `getUpperFilters()`. [1](#0-0) 

**Validation is insufficient:**

`validateBounds()` in `rest/controllers/baseController.js` runs four checks:
- `validateBoundsRange`: rejects only if a single bound has *both* range and equal simultaneously.
- `validateSecondaryBound`: rejects only if secondary is set without primary.
- `validateLowerBounds`: rejects only if secondary has a lower bound but primary lacks `gte`/`eq`.
- `validateUpperBounds`: rejects only if secondary has an upper bound but primary lacks `lte`/`eq`. [2](#0-1) 

A request with `token.id=gte:X&token.id=lte:Y&serialnumber=gte:A&serialnumber=lte:B` passes **all four checks** because primary has both `gte` and `lte` (satisfying the lower/upper bound validators), and no single bound mixes range with equal.

**Three subqueries are generated:**

With both bounds fully populated:
- `getLowerFilters` → `[token_id = X, serial_number >= A]` (non-empty)
- `getInnerFilters` → `[token_id > X, token_id < Y]` (non-empty)
- `getUpperFilters` → `[token_id = Y, serial_number <= B]` (non-empty) [3](#0-2) 

`NftService.getQuery()` then assembles all three into a `UNION ALL` query: [4](#0-3) 

This is confirmed by the existing test case `'token gte and lte, serial gte and lte'` which explicitly expects all three filter arrays to be populated: [5](#0-4) 

**No rate limiting on the REST API:**

The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3/` Java service. The Node.js REST API has no equivalent per-IP or per-request rate limiting for the `/accounts/{id}/nfts` endpoint. The only limit is the response `limit` parameter, capped at 100 by default: [6](#0-5) 

### Impact Explanation
Each crafted request causes the database to execute three independent indexed scans and merge them, compared to one scan for a simple query. With a default `limit` of 100, each subquery can scan up to 100 rows independently. An attacker sending N requests with the dual-bound pattern imposes the same database load as 3N normal requests. On a shared database serving the mirror node (which also serves consensus-critical read paths), sustained amplified load can degrade query throughput, increase latency for all consumers, and in resource-constrained deployments cause connection pool exhaustion or query timeouts. The impact is bounded (fixed 3x, not unbounded), so "total network shutdown" requires sustained volume, but the amplification is free and requires no authentication.

### Likelihood Explanation
The exploit requires zero privileges — the `/api/v1/accounts/{id}/nfts` endpoint is public. The parameter combination is trivially discoverable from the OpenAPI spec or by reading the test suite. The `Bound.parse()` enforcement prevents duplicate operators but explicitly permits one `gte` + one `lte` per field. A single attacker with a modest request rate (e.g., 100 req/s) produces the equivalent of 300 req/s of database load. No authentication, no tokens, no special knowledge required.

### Recommendation
1. **Restrict the dual-bound + dual-secondary combination at validation time**: In `validateBounds()` (or a new `validateNftBounds()` override in `AccountController`), add a check that rejects requests where *both* `primary.hasBound()` and `secondary.hasBound()` are true simultaneously, unless there is a documented business requirement for the 3-subquery path.
2. **Add rate limiting to the REST API**: Implement per-IP request rate limiting (e.g., via an Express middleware using `express-rate-limit`) on the `/accounts/:id/nfts` route, mirroring the bucket4j throttle already present in the web3 service.
3. **Add a query cost budget**: Count the number of non-empty subquery segments before executing and reject (HTTP 400) if the count exceeds a configured threshold (e.g., 2).

### Proof of Concept
```
# No authentication required
GET /api/v1/accounts/0.0.1234/nfts?token.id=gte:0.0.1&token.id=lte:0.0.9999&serialnumber=gte:1&serialnumber=lte:9999999&limit=100

# This causes NftService.getQuery() to build:
# (SELECT ... WHERE account_id=$1 AND token_id=$3 AND serial_number>=$4 ORDER BY ... LIMIT $2)
# UNION ALL
# (SELECT ... WHERE account_id=$1 AND token_id>$5 AND token_id<$6 ORDER BY ... LIMIT $2)
# UNION ALL
# (SELECT ... WHERE account_id=$1 AND token_id=$7 AND serial_number<=$8 ORDER BY ... LIMIT $2)
# ORDER BY ... LIMIT $2

# Repeat at high frequency to amplify DB load by 3x with no authentication.
```

### Citations

**File:** rest/controllers/accountController.js (L66-82)
```javascript
    this.validateFilters(bounds, spenderIdFilters);

    const lower = this.getLowerFilters(bounds);
    const inner = this.getInnerFilters(bounds);
    const upper = this.getUpperFilters(bounds);
    return {
      bounds,
      lower,
      inner,
      upper,
      order,
      ownerAccountId,
      limit,
      spenderIdInFilters,
      spenderIdFilters,
    };
  }
```

**File:** rest/controllers/baseController.js (L56-109)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
  }

  /**
   * Validate that if the primary bound is empty the secondary bound is empty as well.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
  validateSecondaryBound(bounds) {
    if (bounds.primary.isEmpty() && !bounds.secondary.isEmpty()) {
      throw new InvalidArgumentError(
        `${bounds.secondary.filterKey} without a ${bounds.primary.filterKey} parameter filter`
      );
    }
  }

  /**
   * Validate that the Lower Bounds are valid.
   *
   * @param {Bound}[] bounds
   * @throws {InvalidArgumentError}
   */
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

**File:** rest/controllers/baseController.js (L131-183)
```javascript
  getLowerFilters(bounds) {
    let filters = [];
    const {primary, secondary} = bounds;
    if (!secondary.hasBound()) {
      // no secondary bound filters or no secondary filters at all, everything goes into the lower part and there
      // shouldn't be inner or upper part.
      filters = [primary.equal, primary.lower, primary.upper, secondary.equal];
    } else if (primary.hasLower() && secondary.hasLower()) {
      // both have lower. If primary has lower and secondary doesn't have lower, the lower bound of primary
      // will go into the inner part.
      filters = [{...primary.lower, operator: utils.opsMap.eq}, secondary.lower];
    } else if (primary.hasEqual()) {
      filters = [primary.equal, primary.lower, primary.upper, secondary.lower, secondary.equal, secondary.upper];
    }
    return filters.filter((f) => !isNil(f));
  }

  /**
   * Gets filters for the inner part of the multi-union query
   *
   * @param {Bound}[] Bounds
   * @return {{key: string, operator: string, value: *}[]}
   */
  getInnerFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasBound() || !secondary.hasBound()) {
      return [];
    }

    return [
      // if secondary has lower bound, the primary filter should be > ?
      {filter: primary.lower, newOperator: secondary.hasLower() ? utils.opsMap.gt : null},
      // if secondary has upper bound, the primary filter should be < ?
      {filter: primary.upper, newOperator: secondary.hasUpper() ? utils.opsMap.lt : null},
    ]
      .filter((f) => !isNil(f.filter))
      .map((f) => ({...f.filter, operator: f.newOperator || f.filter.operator}));
  }

  /**
   * Gets filters for the upper part of the multi-union query
   *
   * @param {Bound}[] Bounds
   * @return {{key: string, operator: string, value: *}[]}
   */
  getUpperFilters(bounds) {
    const {primary, secondary} = bounds;
    if (!primary.hasUpper() || !secondary.hasUpper()) {
      return [];
    }
    // the upper part should always have primary filter = ?
    return [{...primary.upper, operator: utils.opsMap.eq}, secondary.upper];
  }
```

**File:** rest/service/nftService.js (L93-123)
```javascript
    const subQueries = [lower, inner, upper]
      .filter((filters) => filters.length !== 0)
      .map((filters) =>
        this.getSubQuery(
          filters,
          params,
          accountIdCondition,
          limitClause,
          orderClause,
          spenderIdInFilters,
          spenderIdFilters
        )
      );

    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = this.getSubQuery(
        [],
        params,
        accountIdCondition,
        limitClause,
        orderClause,
        spenderIdInFilters,
        spenderIdFilters
      );
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
    }
```

**File:** rest/__tests__/controllers/accountController.test.js (L325-361)
```javascript
      name: 'token gte and lte, serial gte and lte, spender eq lte gt',
      filters: [
        serialGteFilter,
        serialLteFilter,
        tokenIdGteFilter,
        tokenIdLteFilter,
        spenderEqFilter,
        spenderEqInFilter,
        spenderLteFilter,
        spenderGtFilter,
      ],
      expected: {
        ...defaultExpected,
        bounds: {
          secondary: Bound.create({
            lower: serialGteFilter,
            upper: serialLteFilter,
            filterKey: SERIAL_NUMBER,
            viewModelKey: 'serial_number',
          }),
          primary: Bound.create({
            lower: tokenIdGteFilter,
            upper: tokenIdLteFilter,
            filterKey: TOKEN_ID,
            viewModelKey: 'token_id',
          }),
        },
        lower: [{...tokenIdGteFilter, operator: eq}, serialGteFilter],
        inner: [
          {...tokenIdGteFilter, operator: gt},
          {...tokenIdLteFilter, operator: lt},
        ],
        upper: [{...tokenIdLteFilter, operator: eq}, serialLteFilter],
        spenderIdFilters: [spenderLteFilter, spenderGtFilter],
        spenderIdInFilters: [spenderEqFilter, spenderEqInFilter],
      },
    },
```

**File:** rest/utils.js (L533-553)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};

/**
 * Gets the limit param value, if not exists, return the default; otherwise cap it at max.
 * Note if values is an array, the last one is honored.
 * @param {string[]|string} values Values of the limit param
 * @return {number}
 */
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```
