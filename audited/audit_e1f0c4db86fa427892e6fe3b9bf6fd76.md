### Title
Unauthenticated High-Rate DB Exhaustion via Always-Empty `token.id=lt:1` Filter in `getTokenRelationships()`

### Summary
The `getTokenRelationships()` handler in `rest/controllers/tokenController.js` accepts the `token.id=lt:1` filter as syntactically valid and passes it through to the database without any rate limiting or semantic rejection. Because Hedera token IDs start at 1 or higher, this filter always produces zero results while still executing two database queries per request. With no rate limiting on the REST service and no authentication required, any external user can flood the endpoint with rotating valid account IDs to cause sustained, unnecessary DB load.

### Finding Description
**Code path:**

`rest/controllers/tokenController.js` → `getTokenRelationships()` (lines 66–92):

1. **Line 67**: `EntityService.getEncodedId()` — for a numeric account ID (e.g. `0.0.98`), this is pure in-process parsing; no DB hit.
2. **Line 68**: `EntityService.isValidAccount(accountId)` — executes `SELECT type FROM entity WHERE id = $1` against the DB. This is DB query #1.
3. **Line 72**: `buildAndValidateFilters(req.query, acceptedTokenParameters)` — `token.id=lt:1` passes validation. The `lt` operator is not `ne` (the only rejected operator at line 31), so it is accepted and pushed into `conditions` at line 37.
4. **Line 74**: `TokenService.getTokenAccounts(query)` — executes:
   ```sql
   SELECT ... FROM token_account ta
   WHERE ta.account_id = $1 AND ta.associated = true AND ta.token_id < $3
   ORDER BY ta.token_id asc LIMIT $2
   ```
   with `$3 = 1`. This is DB query #2. Since token IDs in Hedera are ≥ 1, this predicate is always false and always returns zero rows.

**Root cause:** There is no semantic validation that rejects degenerate range filters (e.g. `lt:1` on a field whose minimum value is 1), and there is no rate limiting on the REST Node.js service.

**Why existing checks fail:**

- `authHandler` (`rest/middleware/authHandler.js`, lines 15–36): unauthenticated requests are explicitly allowed through (`if (!credentials) { return; }`). Authentication is entirely optional and only affects the response `limit` cap, not access control.
- No `express-rate-limit` or equivalent middleware is registered in `rest/server.js`. The `ThrottleConfiguration` / `ThrottleManagerImpl` found in the codebase applies exclusively to the `web3` Java service, not the REST Node.js service.
- The optional Redis response cache (`responseCacheUpdateHandler`, line 95) caches responses only when `responseBody` is truthy. The empty-result body `{"tokens":[],"links":{"next":null}}` is truthy, so it is cached — but the cache key is `MD5(req.originalUrl)`. An attacker rotating through different valid account IDs generates a distinct cache key per account, bypassing the cache entirely and forcing a fresh pair of DB queries each time.

### Impact Explanation
Each request with `token.id=lt:1` and a valid account ID causes two DB round-trips that return no useful data. At high request rates across many valid account IDs (all publicly enumerable from the ledger), this creates sustained, artificial DB load with zero legitimate benefit. The impact is service degradation for legitimate users sharing the same DB connection pool — consistent with the "griefing / no economic damage" severity classification.

### Likelihood Explanation
No privileges, credentials, or special knowledge are required beyond knowing any valid account ID (e.g. `0.0.98`, the treasury account, is universally known). The attack is trivially scriptable with a single `curl` loop or any HTTP load tool. The filter value `lt:1` is a stable, always-effective choice that requires no trial-and-error. Repeatability is unlimited.

### Recommendation
1. **Add rate limiting to the REST service**: integrate `express-rate-limit` (or equivalent) as global middleware in `rest/server.js`, applied before route handlers, to cap requests per IP per time window.
2. **Reject semantically degenerate filters**: in `extractTokensRelationshipQuery()` or `buildAndValidateFilters()`, validate that `lt`/`lte` values for `token.id` are greater than the minimum possible token ID (1), and that `gt`/`gte` values are below the maximum, returning HTTP 400 for provably-empty ranges.
3. **Short-circuit before DB on empty-range detection**: if the filter set is provably empty (e.g. `token_id < 1`), return `{"tokens":[],"links":{"next":null}}` immediately without issuing any DB query.

### Proof of Concept
```bash
# Enumerate a set of known valid account IDs (publicly available from the ledger)
ACCOUNTS=(98 2 50 800 1000 2000 5000)

# Flood the endpoint, rotating account IDs to bypass response caching
while true; do
  for ACCT in "${ACCOUNTS[@]}"; do
    curl -s "https://<mirror-node>/api/v1/accounts/0.0.${ACCT}/tokens?token.id=lt:1" -o /dev/null &
  done
  wait
done
```

Each iteration fires N requests (one per account ID), each causing 2 DB queries returning 0 rows. With a large enough account ID list and concurrency, DB connection pool saturation and query queue buildup follow.