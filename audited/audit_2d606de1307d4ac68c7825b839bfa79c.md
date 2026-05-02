### Title
Unbounded `spenderIdInFilters` IN-Clause Replicated Across All UNION Subqueries in `extractNftMultiUnionQuery()` Enables DoS via Expensive NFT Queries

### Summary
`extractNftMultiUnionQuery()` collects all `spender.id=eq:` filters into `spenderIdInFilters` with no count cap beyond the global `maxRepeatedQueryParameters` setting. `NftService.getQuery()` then passes this same array to every UNION subquery (lower, inner, upper), causing the full IN-clause to be evaluated once per subquery. An unauthenticated attacker who sends the maximum number of `spender.id=eq:` values combined with bounds that produce a three-part UNION can force the database to execute three independent full-table-scan-style queries each carrying the large IN-clause, multiplying the cost by three per request.

### Finding Description

**Code path 1 – filter collection with no IN-filter count limit**

`rest/controllers/accountController.js`, lines 58-59:
```js
case filterKeys.SPENDER_ID:
  filter.operator === utils.opsMap.eq ? spenderIdInFilters.push(filter) : spenderIdFilters.push(filter);
```
Every `spender.id=eq:` value is pushed into `spenderIdInFilters` unconditionally. [1](#0-0) 

`validateFilters()` (lines 18-32) only checks that range operators (`lt/lte`, `gt/gte`) are not duplicated and that `ne` is absent. It performs **no check on the length of `spenderIdInFilters`**. [2](#0-1) 

**Code path 2 – IN-clause replicated into every UNION branch**

`rest/service/nftService.js`, lines 93-105:
```js
const subQueries = [lower, inner, upper]
  .filter((filters) => filters.length !== 0)
  .map((filters) =>
    this.getSubQuery(
      filters, params, accountIdCondition, limitClause, orderClause,
      spenderIdInFilters,   // ← same array passed to every branch
      spenderIdFilters
    )
  );
``` [3](#0-2) 

Inside `getSubQuery()` (lines 66-73), the IN-clause is built fresh for each call, appending all spender values to `params` again:
```js
if (!isEmpty(spenderIdInFilters)) {
  const paramsForCondition = spenderIdInFilters.map((filter) => {
    params.push(filter.value);
    return `$${params.length}`;
  });
  conditions.push(`${Nft.SPENDER} in (${paramsForCondition})`);
}
``` [4](#0-3) 

With three active subqueries the final SQL is:
```sql
(SELECT … FROM nft LEFT JOIN entity … WHERE account_id=$1 AND token_id=$3 AND serial_number>=$4 AND spender IN ($5,…,$N) ORDER BY … LIMIT $2)
UNION ALL
(SELECT … FROM nft LEFT JOIN entity … WHERE account_id=$1 AND token_id>$X AND token_id<$Y AND spender IN ($A,…,$M) ORDER BY … LIMIT $2)
UNION ALL
(SELECT … FROM nft LEFT JOIN entity … WHERE account_id=$1 AND token_id=$Z AND serial_number<=$W AND spender IN ($P,…,$Q) ORDER BY … LIMIT $2)
ORDER BY … LIMIT $2
```
Each branch independently scans the `nft` table with the full IN-clause. [5](#0-4) 

**Why the existing guard is insufficient**

`buildFilters()` in `rest/utils.js` (lines 1241-1248) rejects a single parameter key that appears more than `config.query.maxRepeatedQueryParameters` times: [6](#0-5) 

This guard limits the IN-clause width to `maxRepeatedQueryParameters` entries, but it does **not** prevent those entries from being replicated across all three UNION branches. The effective database work is `maxRepeatedQueryParameters × 3` IN-clause evaluations per request, each against the `nft` table with a `LEFT JOIN entity`.

### Impact Explanation
Each crafted request forces the PostgreSQL planner to evaluate up to three independent index-or-sequential scans of the `nft` table, each filtered by a large IN-clause on the `spender` column (which is not the primary key). With a large NFT dataset and concurrent requests from multiple source IPs, connection pool exhaustion and CPU saturation on the database tier are realistic outcomes. Because the mirror node's REST tier is stateless and horizontally scaled, the bottleneck is the shared database; degrading it affects all mirror node instances simultaneously, satisfying the ≥30% processing-node impact threshold.

### Likelihood Explanation
The endpoint `/api/v1/accounts/{id}/nfts` requires no authentication. The attacker needs only:
1. A valid (or even non-existent) account ID.
2. Knowledge of the query parameters, which are publicly documented in `rest/api/v1/openapi.yml`.
3. The ability to send HTTP GET requests concurrently.

No tokens, keys, or privileged access are required. The attack is trivially scriptable and repeatable. [7](#0-6) 

### Recommendation
1. **Cap `spenderIdInFilters` length independently** inside `extractNftMultiUnionQuery()` (or `validateFilters()`), separate from the global `maxRepeatedQueryParameters` limit, to a small value (e.g., 10–25).
2. **Avoid passing `spenderIdInFilters` to every UNION branch.** If the IN-clause is needed, apply it only at the outer wrapper query level (i.e., as a post-filter after the UNION), so it is evaluated once rather than once per branch.
3. **Add per-endpoint rate limiting** on the `/accounts/{id}/nfts` path.
4. **Set a statement timeout** on the database connection pool used by the REST service so runaway queries are killed before they saturate the database.

### Proof of Concept

```
# Step 1 – craft a URL that produces a 3-part UNION (lower + inner + upper)
# token.id=gte:0&token.id=lte:999999999 → lower + inner + upper
# serialnumber=gte:0&serialnumber=lte:999999999 → secondary bounds on each branch
# spender.id=eq:1 … spender.id=eq:N → maximum allowed repeated params → large IN-clause in every branch

GET /api/v1/accounts/0.0.1001/nfts?\
  token.id=gte:0&token.id=lte:999999999&\
  serialnumber=gte:0&serialnumber=lte:999999999&\
  spender.id=1&spender.id=2&spender.id=3&…&spender.id=<maxRepeatedQueryParameters>

# Step 2 – send concurrently from multiple clients
for i in $(seq 1 200); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.1001/nfts?token.id=gte:0&token.id=lte:999999999&serialnumber=gte:0&serialnumber=lte:999999999&spender.id=1&spender.id=2&...&spender.id=N" &
done
wait

# Expected result: database CPU spikes; query latency for all mirror node endpoints
# increases significantly; connection pool exhaustion possible.
```

### Citations

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

**File:** rest/controllers/accountController.js (L58-59)
```javascript
        case filterKeys.SPENDER_ID:
          filter.operator === utils.opsMap.eq ? spenderIdInFilters.push(filter) : spenderIdFilters.push(filter);
```

**File:** rest/service/nftService.js (L66-73)
```javascript
    if (!isEmpty(spenderIdInFilters)) {
      const paramsForCondition = spenderIdInFilters.map((filter) => {
        params.push(filter.value);
        return `$${params.length}`;
      });

      conditions.push(`${Nft.SPENDER} in (${paramsForCondition})`);
    }
```

**File:** rest/service/nftService.js (L93-105)
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
```

**File:** rest/service/nftService.js (L107-123)
```javascript
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

**File:** rest/utils.js (L1241-1248)
```javascript
      if (!isRepeatedQueryParameterValidLength(values)) {
        badParams.push({
          code: InvalidArgumentError.PARAM_COUNT_EXCEEDS_MAX_CODE,
          key,
          count: values.length,
          max: config.query.maxRepeatedQueryParameters,
        });
        continue;
```

**File:** rest/api/v1/openapi.yml (L301-318)
```yaml

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
```
