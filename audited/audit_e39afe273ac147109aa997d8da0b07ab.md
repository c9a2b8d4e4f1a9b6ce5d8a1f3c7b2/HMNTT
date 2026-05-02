### Title
Shared `params` Array Mutation Causes Duplicate Bind Parameters in UNION ALL Queries via `spenderIdInFilters`

### Summary
In `rest/service/nftService.js`, `getQuery()` passes a single shared `params` array to up to three sequential `getSubQuery()` calls. Each call unconditionally appends all `spenderIdInFilters` values to that shared array, so when all three subqueries (lower, inner, upper) are active, the spender IN-clause values are pushed into `params` three times instead of once. An unprivileged user can trigger this by combining token/serial range filters with multiple `spender.id=eq:X` parameters, producing a SQL query with 3× the necessary bind parameters for spender conditions.

### Finding Description

**Exact code path:**

`getQuery()` initializes a single shared `params` array and calls `getSubQuery()` for each non-empty filter set: [1](#0-0) 

Inside `getSubQuery()`, `spenderIdInFilters` values are pushed into the shared `params` on every invocation: [2](#0-1) 

Additionally, `spenderIdFilters` are mutated into the `filters` array and also pushed into `params` on every call: [3](#0-2) 

**Root cause:** `getSubQuery()` treats `spenderIdInFilters` as a per-subquery concern and appends its values to the shared `params` array each time it is called, rather than appending them once before the loop. The implicit assumption is that `params` is local to each subquery, but it is actually shared across all three calls.

**Exploit flow (3-subquery case):**

With `spenderIdInFilters = [{value:15},{value:17},{value:22}]` and all three of `lower`, `inner`, `upper` non-empty:
- After call 1 (lower): params = `[owner, limit, ...lower_vals, 15, 17, 22]`
- After call 2 (inner): params = `[..., ...inner_vals, 15, 17, 22]`
- After call 3 (upper): params = `[..., ...upper_vals, 15, 17, 22]`

Final params contains the spender values at three distinct index ranges (`$5,$6,$7`, `$10,$11,$12`, `$15,$16,$17`), each referenced by a different subquery's `spender in (...)` clause. The SQL is semantically correct but carries 2× redundant bind parameters for spender conditions.

**Why existing checks are insufficient:**

`validateFilters()` in `accountController.js` only rejects multiple range operators and the `ne` operator for `spender.id`; it places no limit on the number of `eq` spender filters: [4](#0-3) 

The `extractNftMultiUnionQuery()` function freely accumulates all `eq` spender filters into `spenderIdInFilters`: [5](#0-4) 

### Impact Explanation
Each crafted request causes PostgreSQL to parse a query with up to 3× the necessary bind parameters for spender conditions. While a single request's overhead is small, the endpoint requires no authentication, and the amplification factor is fixed at 3× (one per UNION ALL branch). Under sustained load from multiple concurrent requests, the cumulative query-parsing overhead on the database increases proportionally to the number of `spender.id=eq` values supplied. For a mirror node serving a high-traffic network, this constitutes a non-network-based resource exhaustion vector against the database tier.

### Likelihood Explanation
Any unauthenticated HTTP client can trigger the maximum 3-subquery path by supplying `token.id=gte:X&token.id=lte:Y&serial.number=gte:A&serial.number=lte:B` alongside multiple `spender.id=eq:Z` parameters. No special knowledge, credentials, or tooling beyond a standard HTTP client is required. The attack is trivially repeatable and scriptable.

### Recommendation
Move the `spenderIdInFilters` (and `spenderIdFilters`) parameter-appending logic out of `getSubQuery()` and into `getQuery()`, appending those values to `params` exactly once before the subquery loop. Pass pre-computed `$N` placeholder strings (or a starting offset) into `getSubQuery()` so each subquery references the already-appended values rather than re-appending them. For example:

```js
// In getQuery(), before the .map():
const spenderInPlaceholders = spenderIdInFilters.map((f) => {
  params.push(f.value);
  return `$${params.length}`;
});
const spenderInCondition = spenderInPlaceholders.length
  ? `${Nft.SPENDER} in (${spenderInPlaceholders})`
  : null;
// Pass spenderInCondition (a string) into getSubQuery() instead of the raw filter array.
```

This ensures spender values appear in `params` exactly once regardless of how many UNION ALL branches are generated.

### Proof of Concept

```
GET /api/v1/accounts/0.0.1234/nfts?token.id=gte:100&token.id=lte:200&serial.number=gte:1&serial.number=lte:50&spender.id=15&spender.id=17&spender.id=22
```

**Expected (correct) params:** `[accountId, limit, 2, 100, 15, 17, 22, 2, 8, 8, 200]` — spender values appear once.

**Actual params produced:** `[accountId, limit, ...lower_vals, 15, 17, 22, ...inner_vals, 15, 17, 22, ...upper_vals, 15, 17, 22]` — spender values 15, 17, 22 each appear three times at distinct indices, and the generated SQL contains three separate `spender in ($N,$M,$P)` clauses referencing those duplicate entries.

Confirm by calling `NftService.getQuery({lower:[...], inner:[...], upper:[...], spenderIdInFilters:[{value:15},{value:17},{value:22}], spenderIdFilters:[], ownerAccountId:1, limit:20, order:'desc'})` and inspecting `result.params.length` — it will be 17 instead of the expected 11.

### Citations

**File:** rest/service/nftService.js (L56-63)
```javascript
    filters.push(...spenderIdFilters);
    const conditions = [
      accountIdCondition,
      ...filters.map((filter) => {
        params.push(filter.value);
        const column = NftService.columns[filter.key];
        return `${column}${filter.operator}$${params.length}`;
      }),
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

**File:** rest/service/nftService.js (L86-105)
```javascript
    const params = [ownerAccountId, limit];
    const accountIdCondition = `${Nft.ACCOUNT_ID} = $1`;
    const limitClause = super.getLimitQuery(2);
    const orderClause = super.getOrderByQuery(
      ...NftService.orderByColumns.map((column) => OrderSpec.from(column, order))
    );

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
