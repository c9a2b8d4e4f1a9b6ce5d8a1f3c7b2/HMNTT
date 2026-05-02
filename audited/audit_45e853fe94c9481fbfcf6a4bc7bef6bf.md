### Title
Unauthenticated Resource Exhaustion via Multi-Subquery Path in Token Allowances Endpoint

### Summary
The `/api/v1/accounts/{id}/allowances/tokens` endpoint is publicly accessible with no authentication or rate limiting. Any external user can supply `spender.id=gte:X&token.id=gte:Y` query parameters to trigger the multi-subquery (`UNION ALL`) code path in `getQuery()`, which issues up to three separate database subqueries per request. Flooding this endpoint concurrently exhausts the shared database connection pool, causing a non-network DoS for all other users.

### Finding Description

**Exact code location:** `rest/service/tokenAllowanceService.js`, `getQuery()`, lines 63–74.

```js
// lines 63-74
const subQueries = [lower, inner, upper]
  .filter((filters) => filters.length !== 0)
  .map((filters) => this.getSubQuery(filters, params, accountIdCondition, limitClause, orderClause));

// ...
} else {
  sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
}
``` [1](#0-0) 

**Root cause:** The `lower`, `inner`, and `upper` filter arrays are populated entirely from user-supplied query parameters by `extractTokenMultiUnionQuery()` in the controller. When a caller provides both a SPENDER_ID lower bound (`gte`) and a TOKEN_ID lower bound (`gte`), `getLowerFilters` and `getInnerFilters` both return non-empty arrays, causing two subqueries to be emitted. Adding an upper bound (`lte`) on both produces all three subqueries. [2](#0-1) 

Each subquery is a full `SELECT * FROM token_allowance WHERE … ORDER BY spender, token_id LIMIT $2`, and the outer query adds another `ORDER BY` + `LIMIT` pass over the merged result set. [3](#0-2) 

**Why existing checks are insufficient:** `validateBounds()` only rejects logically invalid combinations (e.g., `ne`, range + equal, missing primary bound). It does not prevent the multi-subquery path from being reached; it is the *intended* path for valid range queries. [4](#0-3) 

No rate-limiting middleware was found anywhere in the application JS code. The only reference to rate limiting in JS files is inside a test utility (`integrationUtils.js`), not in any production middleware or route configuration. [5](#0-4) 

The database pool is a global singleton accessed via `pool()` in `BaseService`, shared across all concurrent requests with no per-endpoint concurrency cap visible in the codebase. [6](#0-5) 

### Impact Explanation
Each request to the multi-subquery path consumes up to 3× the database worker capacity of a baseline request. With no rate limiting, an attacker issuing thousands of concurrent requests with `?spender.id=gte:1&token.id=gte:1` saturates the shared DB connection pool. Once the pool is exhausted, all other API endpoints that share the same pool (the entire mirror-node REST API) begin queuing or rejecting requests, constituting a full non-network DoS for legitimate users. The `SELECT *` projection (no column restriction) maximizes per-row data transfer cost. [7](#0-6) 

### Likelihood Explanation
The endpoint is unauthenticated and publicly documented in the OpenAPI spec. The triggering parameters (`spender.id=gte:X&token.id=gte:Y`) are explicitly described as valid and supported in the API documentation. No special knowledge, credentials, or network position is required. The attack is trivially scriptable with any HTTP load-testing tool (e.g., `ab`, `wrk`, `hey`) and is fully repeatable. [8](#0-7) 

### Recommendation
1. **Rate limiting:** Apply per-IP (and optionally per-account-ID path parameter) rate limiting at the application layer (e.g., `express-rate-limit`) on all allowance endpoints, not just at the infrastructure level.
2. **DB pool concurrency cap:** Configure an explicit `max` on the database connection pool and enforce a per-request query timeout so a flood of expensive queries cannot hold connections indefinitely.
3. **Query cost cap:** Consider enforcing a PostgreSQL `statement_timeout` for REST API connections to bound the maximum wall-clock time any single subquery can consume.
4. **Restrict multi-subquery amplification:** If the three-subquery `UNION ALL` pattern is only needed for pagination continuations (not initial requests), gate it behind a cursor/token check rather than allowing arbitrary range combinations on every request.

### Proof of Concept

**Preconditions:** No credentials required. Any valid account ID in the path (e.g., `0.0.1`) suffices; the account need not have any allowances.

**Trigger (two-subquery path):**
```
GET /api/v1/accounts/0.0.1/allowances/tokens?spender.id=gte:1&token.id=gte:1
```
This causes `lower = [{spender, eq, 1}, {token_id, gte, 1}]` and `inner = [{spender, gt, 1}]`, producing two subqueries joined with `UNION ALL`.

**Three-subquery path:**
```
GET /api/v1/accounts/0.0.1/allowances/tokens?spender.id=gte:1&spender.id=lte:9999999&token.id=gte:1&token.id=lte:9999999
```
This populates all three of `lower`, `inner`, and `upper`, producing three subqueries.

**DoS flood:**
```bash
# Using 'hey' HTTP load generator
hey -n 50000 -c 500 \
  "http://<mirror-node-host>/api/v1/accounts/0.0.1/allowances/tokens?spender.id=gte:1&spender.id=lte:9999999&token.id=gte:1&token.id=lte:9999999"
```

**Result:** The database connection pool is saturated. Concurrent legitimate requests to any mirror-node REST endpoint begin timing out or receiving 503 errors until the flood stops.

### Citations

**File:** rest/service/tokenAllowanceService.js (L12-12)
```javascript
  static accountTokenAllowanceQuery = `select * from ${TokenAllowance.tableName}`;
```

**File:** rest/service/tokenAllowanceService.js (L40-45)
```javascript
    return [
      TokenAllowanceService.accountTokenAllowanceQuery,
      `where ${conditions.join(' and ')}`,
      orderClause,
      limitClause,
    ].join('\n');
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

**File:** rest/controllers/baseController.js (L56-61)
```javascript
  validateBounds(bounds) {
    this.validateBoundsRange(bounds);
    this.validateSecondaryBound(bounds);
    this.validateLowerBounds(bounds);
    this.validateUpperBounds(bounds);
  }
```

**File:** rest/routes/accountRoute.js (L1-1)
```javascript
// SPDX-License-Identifier: Apache-2.0
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/api/v1/openapi.yml (L290-330)
```yaml
  /api/v1/accounts/{idOrAliasOrEvmAddress}/allowances/tokens:
    get:
      summary: Get fungible token allowances for an account
      description: |
        Returns information for fungible token allowances for an account.

        ## Ordering
        The order is governed by a combination of the spender id and the token id values, with spender id being the parent column.
        The token id value governs its order within the given spender id.

        Note: The default order for this API is currently ASC

        ## Filtering
        When filtering there are some restrictions enforced to ensure correctness and scalability.

        **The table below defines the restrictions and support for the endpoint**

        | Query Param   | Comparison Operator | Support | Description           | Example |
        | ------------- | ------------------- | ------- | --------------------- | ------- |
        | spender.id    | eq                  | Y       | Single occurrence only. | ?spender.id=X |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. | ?spender.id=lte:X |
        |               | gt(e)               | Y       | Single occurrence only. | ?spender.id=gte:X |
        | token.id      | eq                  | Y       | Single occurrence only. Requires the presence of a **spender.id** query | ?token.id=lt:Y |
        |               | ne                  | N       | | |
        |               | lt(e)               | Y       | Single occurrence only. Requires the presence of an **lte** or **eq** **spender.id** query | ?spender.id=lte:X&token.id=lt:Y |
        |               | gt(e)               | Y       | Single occurrence only. Requires the presence of an **gte** or **eq** **spender.id** query | ?spender.id=gte:X&token.id=gt:Y |

        Both filters must be a single occurrence of **gt(e)** or **lt(e)** which provide a lower and or upper boundary for search.

      operationId: getTokenAllowances
      parameters:
        - $ref: "#/components/parameters/accountIdOrAliasOrEvmAddressPathParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
        - $ref: "#/components/parameters/spenderIdQueryParam"
        - $ref: "#/components/parameters/tokenIdQueryParam"
      responses:
        200:
          description: OK
          content:
```
