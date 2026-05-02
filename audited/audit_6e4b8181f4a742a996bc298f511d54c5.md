### Title
Unparameterized IN Clause in `getInClauseSubQuery()` Enables Query-Plan-Cache Exhaustion DoS

### Summary
`getInClauseSubQuery()` in `rest/service/tokenService.js` directly interpolates validated numeric token IDs into the SQL string instead of using PostgreSQL bind parameters, despite receiving the `params` array for exactly that purpose. Any unauthenticated caller can supply up to `maxRepeatedQueryParameters` (100) distinct `token.id=eq:X` values per request, producing a unique SQL string on every call, forcing PostgreSQL to re-parse and re-plan the query each time. Under sustained concurrent load this exhausts DB CPU on planning work, degrading or blocking all other queries served by the mirror node's database.

### Finding Description

**Exact code path:**

`rest/controllers/tokenController.js` → `getTokenRelationships` (line 72) calls `utils.buildAndValidateFilters`, which validates each `token.id` value via `EntityId.isValidEntityId` and then `formatComparator` converts it to a numeric encoded ID (Number or BigInt) via `EntityId.parseString(...).getEncodedId()` (lines 1415–1420 of `rest/utils.js`). The resulting numeric values are stored in `inConditions` and passed to `TokenService.getTokenAccounts` → `getTokenRelationshipsQuery` → `getInClauseSubQuery`.

**Root cause — `getInClauseSubQuery` never uses the `params` array:**

```js
// rest/service/tokenService.js  lines 78-87
getInClauseSubQuery(inConditions, params) {   // params received but NEVER written to
    const tokenIdInParams = [];
    inConditions.forEach((condition) => {
      tokenIdInParams.push(condition.value);  // numeric BigInt/Number values
    });

    if (!isEmpty(tokenIdInParams)) {
      // values interpolated directly into the SQL string
      return ` and ${TokenAccount.getFullName(TokenAccount.TOKEN_ID)} in (${tokenIdInParams})`;
    }
  }
```

With 100 unique token IDs the emitted SQL fragment is:

```sql
and ta.token_id in (1,2,3,4,...,100)
```

Every request with a different set of 100 IDs produces a structurally different SQL string. PostgreSQL treats each as a brand-new query: it must lex, parse, and plan it from scratch, and the resulting plan cannot be cached or reused.

**Why existing checks are insufficient:**

`buildFilters` (lines 1241–1248 of `rest/utils.js`) enforces `maxRepeatedQueryParameters ≤ 100`, which caps the IN-clause width but does nothing to prevent the unparameterized interpolation. The validation pipeline (`EntityId.isValidEntityId` → `formatComparator`) correctly prevents SQL injection but does not fix the missing parameterization. The `params` array is passed into `getInClauseSubQuery` but is never populated with the IN-clause values, so the pg driver executes a raw, unparameterized string.

### Impact Explanation

Every concurrent attacker request with a fresh set of 100 distinct token IDs forces a full PostgreSQL parse+plan cycle. Under sustained parallel load (e.g., hundreds of requests/second from a single host or a small botnet), the DB server's CPU is consumed by planning work rather than query execution, causing latency spikes and timeouts for all other mirror-node API consumers. The mirror node's database is shared across all REST endpoints; saturation of the planner thread pool degrades the entire service. This is a denial-of-service against the mirror node's read API, not the Hedera consensus layer directly.

### Likelihood Explanation

The endpoint `/api/v1/accounts/{id}/tokens` is publicly accessible with no authentication. An attacker needs only an HTTP client and knowledge of the query parameter. Generating 100 unique valid token IDs per request is trivial (sequential integers `1`–`100`, `101`–`200`, etc.). The attack is fully repeatable, requires no special privileges, and can be amplified with modest concurrency. No rate-limiting or query-complexity budget is applied at the application layer.

### Recommendation

Populate the `params` array inside `getInClauseSubQuery` and emit positional placeholders instead of interpolating values:

```js
getInClauseSubQuery(inConditions, params) {
    if (isEmpty(inConditions)) return '';
    const placeholders = inConditions.map((condition) => {
        params.push(condition.value);
        return `$${params.length}`;
    });
    return ` and ${TokenAccount.getFullName(TokenAccount.TOKEN_ID)} in (${placeholders.join(',')})`;
}
```

Alternatively, use a single `= any($N)` bind with an array value, consistent with how `tokenCacheQuery` already handles multi-value lookups (line 38 of `tokenService.js`).

### Proof of Concept

```bash
# Generate 100 unique token IDs per request, rotate the set each iteration
for i in $(seq 1 500); do
  OFFSET=$(( (i - 1) * 100 ))
  PARAMS=$(seq $((OFFSET+1)) $((OFFSET+100)) | \
           awk '{printf "token.id=%s&", $1}' | sed 's/&$//')
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.98/tokens?${PARAMS}" &
done
wait
```

Each of the 500 concurrent requests carries a distinct 100-element IN clause. PostgreSQL receives 500 unique SQL strings simultaneously, forcing 500 independent parse+plan cycles. Monitor `pg_stat_activity` and CPU utilisation on the DB host; planning CPU will spike and query latency for all other endpoints will increase proportionally.