### Title
Unbounded `spenderIdInFilters` IN Clause Duplicated Across All UNION ALL Sub-Queries, Multiplying DB Load

### Summary
An unprivileged user can send up to `maxRepeatedQueryParameters` `spender.id=eq:` values to `/accounts/:id/nfts`. In `NftService.getQuery`, the full `spenderIdInFilters` array is passed into every `getSubQuery` call — one per non-empty bound tier (lower, inner, upper) — so the IN clause is appended to each sub-query independently. Combined with token/serial range filters that activate all three tiers, this produces a UNION ALL of three sub-queries each carrying the full IN clause, multiplying DB evaluation work by up to 3× per request with no additional privilege required.

### Finding Description
**Code path:**

In `rest/controllers/accountController.js` lines 58–59, every `spender.id=eq:` filter is collected into `spenderIdInFilters` with no count cap beyond the global `maxRepeatedQueryParameters`: [1](#0-0) 

`validateFilters` (lines 18–32) only validates `spenderIdFilters` (range operators) for duplicate bounds and `ne` — it never checks the size of `spenderIdInFilters`: [2](#0-1) 

In `rest/service/nftService.js` lines 93–105, `getQuery` iterates over `[lower, inner, upper]` and calls `getSubQuery` for each non-empty tier, passing the **same** `spenderIdInFilters` reference every time: [3](#0-2) 

Inside `getSubQuery` (lines 66–73), the IN clause is built fresh for each call, pushing all `spenderIdInFilters` values into the shared `params` array and emitting `spender in ($X,$Y,...)` as a new condition: [4](#0-3) 

**Root cause:** The failed assumption is that `spenderIdInFilters` is a one-time filter. Instead it is re-evaluated and re-appended inside every sub-query of the UNION ALL. The only guard (`maxRepeatedQueryParameters` in `buildFilters`) caps the IN clause width but does not prevent its multiplication across sub-queries. [5](#0-4) 

### Impact Explanation
With `maxRepeatedQueryParameters` (default value read from `config.query.maxRepeatedQueryParameters`) `spender.id=eq:` values and a request that activates all three bound tiers (lower + inner + upper), the DB receives a UNION ALL of three sub-queries each containing the full IN clause. Each sub-query independently scans the `nft` table filtered by `account_id`, the token/serial bounds, **and** the full IN list. This is a 3× amplification of the IN-clause evaluation cost per request. Repeated concurrent requests from a single unauthenticated client can sustain elevated DB CPU/IO with no rate-limiting beyond the global repeated-parameter cap.

### Likelihood Explanation
No authentication or special privilege is required. The endpoint is publicly accessible. The attacker only needs to know the API format (`spender.id=eq:X`) and how to trigger all three bound tiers (e.g., `token.id=gt:A&token.id=lt:B&serialnumber=gt:C`). The attack is trivially scriptable and repeatable.

### Recommendation
1. Add an explicit cap on `spenderIdInFilters.length` inside `extractNftMultiUnionQuery` (e.g., reject if `> 1` or a small configured maximum) or inside `validateFilters`.
2. Alternatively, pass `spenderIdInFilters` only to the outermost wrapper query rather than to every sub-query, so the IN filter is applied once after the UNION ALL.
3. Consider rate-limiting the `/accounts/:id/nfts` endpoint per source IP.

### Proof of Concept
```
# Trigger all three bound tiers (lower + inner + upper) and max IN-clause width:
GET /api/v1/accounts/0.0.1001/nfts
  ?token.id=gt:100
  &token.id=lt:9999
  &serialnumber=gt:1
  &spender.id=eq:1000
  &spender.id=eq:2000
  &spender.id=eq:3000
  ... (up to maxRepeatedQueryParameters values)
```

The resulting SQL will be a UNION ALL of three sub-queries, each containing `AND spender IN ($N, $N+1, ..., $N+K)` with K = number of `spender.id=eq:` values supplied. Sending this request in a tight loop from a single unauthenticated client produces sustained amplified DB load.

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
