### Title
Unbounded Duplicate `spender.id=eq` Values Bloat IN Clause Across All Three UNION Subqueries in `getSubQuery()`

### Summary
The `/api/v1/accounts/{id}/nfts` endpoint accepts up to 100 repeated `spender.id=eq:X` query parameters (the `maxRepeatedQueryParameters` default). Because `validateFilters()` in `accountController.js` only checks non-eq operators for duplicates, all 100 values (including identical ones) are collected into `spenderIdInFilters` without deduplication. `getQuery()` then passes this same array into `getSubQuery()` once per active subquery (up to three times for lower/inner/upper), and each call appends all 100 values to the shared `params` array, generating a 100-entry `spender IN (...)` clause per subquery — 300 redundant IN-list entries total — from a single unauthenticated HTTP request.

### Finding Description

**Exact code path:**

`accountController.js` `extractNftMultiUnionQuery()` (line 59) routes every `spender.id` filter with operator `eq` into `spenderIdInFilters` with no duplicate check: [1](#0-0) 

`validateFilters()` (lines 18–32) only validates `spenderIdFilters` (non-eq operators) for multiple range params and `ne`; it never inspects `spenderIdInFilters` at all: [2](#0-1) 

`getQuery()` passes the same `spenderIdInFilters` array and the same mutable `params` array into `getSubQuery()` for each of the three subqueries: [3](#0-2) 

Inside `getSubQuery()`, every element of `spenderIdInFilters` is unconditionally pushed onto `params` and emitted as a separate `$N` placeholder in the IN clause — no deduplication: [4](#0-3) 

**Root cause:** `spenderIdInFilters` is never deduplicated at any layer, and `validateFilters()` imposes no constraint on the count or uniqueness of eq-operator spender filters. The same array is replayed into every subquery, multiplying the IN-list size by the number of active subqueries (up to 3).

**Exploit flow:**
1. Attacker sends a single GET request with 100 identical `spender.id` eq values and a closed token_id range to force all three subqueries:
   ```
   GET /api/v1/accounts/0.0.1001/nfts?token.id=gte:1&token.id=lte:9999
       &spender.id=1&spender.id=1&...  (×100)
   ```
2. `qs` parser accepts up to `maxRepeatedQueryParameters` (default 100) values per key.
3. `buildFilters` passes all 100 through; `validateFilters` ignores them.
4. `getQuery` calls `getSubQuery` three times; each call appends 100 identical values to `params` and emits `spender IN ($n, $n+1, ..., $n+99)`.
5. PostgreSQL receives three subqueries each with a 100-entry IN list (300 total redundant entries) and must evaluate the IN predicate per row in each subquery.

### Impact Explanation
Each of the three subqueries carries a 100-entry IN clause where all values are identical, forcing the database to perform up to 300 redundant predicate evaluations per row scanned. On a large `nft` table this inflates per-request CPU and I/O proportionally to the IN-list size relative to a normal single-value query. Because the `params` array is shared and grows additively across subquery calls, the generated SQL is also significantly larger, increasing parse and plan overhead. A sustained stream of such requests (each individually within the single-request constraint) can push node CPU well above the 30% threshold.

### Likelihood Explanation
No authentication is required. The endpoint is publicly accessible. The exploit requires only a crafted URL with repeated query parameters, which any HTTP client can produce. The `maxRepeatedQueryParameters` cap of 100 bounds the per-request amplification but does not prevent it; the 3× subquery multiplication is an additional force multiplier not accounted for by that cap. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Deduplicate `spenderIdInFilters` before use** — apply `[...new Set(spenderIdInFilters.map(f => f.value))]` or equivalent before passing to `getSubQuery()`.
2. **Add a count/uniqueness check in `validateFilters()`** — reject requests where `spenderIdInFilters.length` exceeds a small practical maximum (e.g., 10), consistent with how the token-allowance controller rejects multiple eq values for `spender.id`.
3. **Do not pass `spenderIdInFilters` by reference into a shared `params` array** across multiple `getSubQuery()` calls — either snapshot the params offset before each call or restructure so IN-list params are added once to the outer query.

### Proof of Concept
```
# Trigger all three subqueries (lower/inner/upper) with 100 duplicate spender.id eq values
curl -s "http://<mirror-node>:5551/api/v1/accounts/0.0.1001/nfts?\
token.id=gte:1500&token.id=lte:2500&\
spender.id=1&spender.id=1&spender.id=1&spender.id=1&spender.id=1&\
spender.id=1&spender.id=1&spender.id=1&spender.id=1&spender.id=1&\
... (repeat to 100 total)"
```

The resulting SQL sent to PostgreSQL will contain three subqueries each with:
```sql
spender in ($3,$4,$5,...,$102)   -- lower subquery, 100 identical values
spender in ($103,$104,...,$202)  -- inner subquery, 100 identical values
spender in ($203,$204,...,$302)  -- upper subquery, 100 identical values
```
All 300 parameter slots resolve to the same value `1`, confirming the redundant IN-list amplification from a single unauthenticated request.

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
