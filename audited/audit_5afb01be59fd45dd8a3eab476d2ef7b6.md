### Title
Unauthenticated Maximum-Range UNION ALL Query Triggers Amplified DB Load on `/accounts/:id/nfts`

### Summary
An unprivileged external user can craft a request with `token.id=gte:1&token.id=lte:9223372036854775807&serialnumber=gte:1&serialnumber=lte:9223372036854775807` that passes all validation in `extractNftMultiUnionQuery()` and forces `NftService.getQuery()` to emit the maximum-complexity three-part `UNION ALL` SQL query. Because the REST API has no per-endpoint rate limiting, an attacker can flood this endpoint to sustain elevated DB load and degrade service for other users.

### Finding Description

**Exact code path:**

`rest/routes/accountRoute.js:15` → `AccountController.getNftsByAccountId` (`rest/controllers/accountController.js:90-103`) → `extractNftMultiUnionQuery` (`rest/controllers/accountController.js:34-82`) → `validateFilters` / `validateBounds` (`rest/controllers/baseController.js:56-123`) → `getLowerFilters` / `getInnerFilters` / `getUpperFilters` (`rest/controllers/baseController.js:131-183`) → `NftService.getQuery` (`rest/service/nftService.js:84-126`).

**Root cause — failed assumption in `validateLowerBounds` and `validateUpperBounds`:**

`validateLowerBounds` (`rest/controllers/baseController.js:83-92`) throws only when `secondary.hasLower()` is true AND `primary.lower.operator === opsMap.gt` (strict `>`). With `token.id=gte:1`, `primary.lower.operator` is `gte`, so the condition `primary.lower.operator === opsMap.gt` is `false`, and the whole guard evaluates to `false` — no error is thrown. [1](#0-0) 

Identically, `validateUpperBounds` (`rest/controllers/baseController.js:100-108`) only rejects `lt` (strict `<`); `lte` passes silently. [2](#0-1) 

**Exploit flow:**

With both bounds using `gte`/`lte`, all four filters are accepted. `getLowerFilters` sees `primary.hasLower() && secondary.hasLower()` → true, producing `lower = [{token_id = 1}, {serial_number >= 1}]`. `getInnerFilters` sees both bounds present → `inner = [{token_id > 1}, {token_id < MAX_LONG}]`. `getUpperFilters` sees both uppers → `upper = [{token_id = MAX_LONG}, {serial_number <= MAX_LONG}]`. [3](#0-2) 

All three filter arrays are non-empty, so `NftService.getQuery` takes the `subQueries.length > 1` branch and emits:

```sql
(SELECT … FROM nft LEFT JOIN entity e … WHERE account_id=$1 AND token_id=1 AND serial_number>=$3 … LIMIT $2)
UNION ALL
(SELECT … FROM nft LEFT JOIN entity e … WHERE account_id=$1 AND token_id>1 AND token_id<9223372036854775807 … LIMIT $2)
UNION ALL
(SELECT … FROM nft LEFT JOIN entity e … WHERE account_id=$1 AND token_id=9223372036854775807 AND serial_number<=$4 … LIMIT $2)
ORDER BY token_id desc, serial_number desc LIMIT $2
``` [4](#0-3) 

The inner subquery spans the entire valid `token_id` space for the account. Each subquery independently executes a `LEFT JOIN entity` and an index range scan up to `limit` rows; the outer query then merges and re-sorts up to `3 × limit` rows. This is structurally 3× heavier than a single-subquery request.

**Why existing checks are insufficient:**

`validateBoundsRange` only rejects mixing range+equal on the same field. `validateSecondaryBound` only rejects a secondary filter without a primary. `validateLowerBounds`/`validateUpperBounds` only enforce operator strictness (`gt` vs `gte`, `lt` vs `lte`), not range magnitude. `validateFilters` in `AccountController` adds only spender-specific checks. [5](#0-4) 

The REST API server (`rest/server.js`) applies no per-endpoint rate limiting; the throttle infrastructure found in the codebase (`web3/src/main/java/…/ThrottleConfiguration.java`) belongs to the separate web3 Java service and does not protect this Node.js endpoint. [6](#0-5) 

### Impact Explanation

Every request with this parameter pattern forces three independent DB subqueries plus a merge sort, each touching the `nft` table and joining `entity`. Sustained concurrent flooding multiplies DB CPU and I/O by a factor of ~3 compared to normal pagination requests. This degrades query latency for all other API consumers sharing the same DB connection pool. No authentication, API key, or account balance is required, making the attack free and repeatable. Severity is medium (griefing / availability degradation with no direct economic loss to network participants).

### Likelihood Explanation

The attack requires zero privileges — any HTTP client can reach the public REST endpoint. The exact parameter string is trivially derived from the API documentation (the OpenAPI spec explicitly lists `gte`/`lte` as supported operators for both `token.id` and `serialnumber`). [7](#0-6) 

The request is idempotent and stateless, so it can be scripted and parallelised with no coordination overhead. Repeatability is unlimited.

### Recommendation

1. **Add a range-width guard in `extractNftMultiUnionQuery`**: if both `primary.lower` and `primary.upper` are present simultaneously with `secondary.lower` and `secondary.upper`, reject the request or require the caller to narrow the range (e.g., enforce `primary.upper.value - primary.lower.value ≤ configurable_max`).
2. **Alternatively, collapse the three-part UNION ALL into a single query** when the full range is open-ended (i.e., when `inner` would span the entire key space), falling back to simple pagination.
3. **Add per-IP or per-endpoint rate limiting** in the REST Node.js middleware (e.g., `express-rate-limit`) for the `/accounts/:id/nfts` route, independent of the web3 throttle layer.
4. **Add a DB-level statement timeout** for queries originating from this endpoint to bound worst-case execution time.

### Proof of Concept

```bash
# Trigger the maximum three-part UNION ALL on any valid account
curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.1001/nfts?\
token.id=gte:1&token.id=lte:9223372036854775807&\
serialnumber=gte:1&serialnumber=lte:9223372036854775807&\
limit=100"

# Flood to sustain DB load (no auth required)
for i in $(seq 1 200); do
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.1001/nfts?\
token.id=gte:1&token.id=lte:9223372036854775807&\
serialnumber=gte:1&serialnumber=lte:9223372036854775807&\
limit=100" &
done
wait
```

Expected: HTTP 200 with up to 100 NFTs returned; DB executes a three-part `UNION ALL` with the inner subquery ranging over `token_id > 1 AND token_id < 9223372036854775807` for every concurrent request.

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

**File:** rest/controllers/baseController.js (L100-108)
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

**File:** rest/controllers/accountController.js (L18-32)
```javascript
  validateFilters(bounds, spenderIdFilters) {
    this.validateBounds(bounds);

    const spenderOperators = spenderIdFilters.map((f) => f.operator);
    if (
      spenderOperators.filter((o) => o === utils.opsMap.lte || o === utils.opsMap.lt).length > 1 ||
      spenderOperators.filter((o) => o === utils.opsMap.gte || o === utils.opsMap.gt).length > 1
    ) {
      throw new InvalidArgumentError(`Multiple range params not allowed for spender.id`);
    }

    if (spenderIdFilters.some((f) => f.operator === utils.opsMap.ne)) {
      throw new InvalidArgumentError(`Not equals (ne) comparison operator is not supported`);
    }
  }
```

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** rest/api/v1/openapi.yml (L128-144)
```yaml
        | Query Param   | Comparison Operator | Support | Description           | Example |
        | ------------- | ------------------- | ------- | --------------------- | ------- |
        | token.id      | eq                  | Y       | Single occurrence only. | ?token.id=X |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. | ?token.id=lte:X |
        |               | gt(e)               | Y       | Single occurrence only. | ?token.id=gte:X |
        | serialnumber  | eq                  | Y       | Single occurrence only. Requires the presence of a **token.id** query | ?serialnumber=Y |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. Requires the presence of an **lte** or **eq** **token.id** query | ?token.id=lte:X&serialnumber=lt:Y |
        |               | gt(e)               | Y       | Single occurrence only. Requires the presence of an **gte** or **eq** **token.id** query | ?token.id=gte:X&serialnumber=gt:Y |
        | spender.id    | eq                  | Y       | | ?spender.id=Z |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | | ?spender.id=lt:Z |
        |               | gt(e)               | Y       | | ?spender.id=gt:Z |

        Note: When searching across a range for individual NFTs a **serialnumber** with an additional **token.id** query filter must be provided.
        Both filters must be a single occurrence of **gt(e)** or **lt(e)** which provide a lower and or upper boundary for search.
```
