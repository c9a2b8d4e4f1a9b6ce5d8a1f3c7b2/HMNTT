### Title
Unbounded CTE in `tokenAccountCte` Enables Unauthenticated DB Resource Exhaustion via `account.id` Filter

### Summary
Any unauthenticated user can supply a valid `account.id` query parameter to `GET /api/v1/tokens`, forcing `getTokensRequest()` to build and execute a query using the `tokenAccountCte` CTE. This CTE contains no `LIMIT` clause, causing it to materialize all `token_account` rows for the given account before the outer query applies the result limit. By flooding requests with varying account IDs (to bypass the response cache), an attacker can saturate the small DB connection pool and degrade service for all users.

### Finding Description
**Code path:**

In `rest/tokens.js`, `getTokensRequest()` (lines 360–422) checks for the presence of `account.id` in the query string with no authentication requirement:

```js
// rest/tokens.js lines 378–384
const accountId = req.query[filterKeys.ACCOUNT_ID];
if (accountId) {
  conditions.push('ta.associated is true');
  getTokensSqlQuery.unshift(tokenAccountCte);
  getTokensSqlQuery.push(tokenAccountJoinQuery);
  getTokenSqlParams.push(EntityId.parseString(accountId, ...).getEncodedId());
}
```

The `tokenAccountCte` constant (lines 121–126) is:

```sql
with ta as (
  select *
  from token_account
  where account_id = $1
  order by token_id        -- no LIMIT here
)
```

The CTE materializes **all** `token_account` rows for the given `account_id` before the outer query applies `LIMIT $N`. The non-account path (`tokensSelectQuery` + `entityIdJoinQuery`) is a two-table join with the limit applied directly; the account path adds a third table and an unbounded intermediate result set.

**Validation bypass:** `validateTokenQueryFilter` (lines 309–358) only checks that the value is a syntactically valid entity ID (`EntityId.isValidEntityId(val)`). Any value like `0.0.1` passes. No authentication or privilege check exists.

**Cache bypass:** The response cache key is `MD5(req.originalUrl)` (line 152 of `responseCacheHandler.js`). An attacker rotates through different valid account IDs (`?account.id=0.0.1`, `?account.id=0.0.2`, …) to ensure every request is a cache miss and hits the database.

**Root cause:** The `tokenAccountCte` CTE is missing a `LIMIT` clause, and the endpoint imposes no per-IP or per-user rate limit for unauthenticated callers.

### Impact Explanation
The DB connection pool is configured with `maxConnections: 10` and `statementTimeout: 20000` ms. Each flooded request with a high-association account ID holds a connection for the duration of the CTE scan (up to 20 s). With 10 concurrent malicious requests, the pool is fully saturated, causing all other API endpoints (transactions, accounts, balances, etc.) to queue or time out. This is a service-wide degradation with no economic damage to network participants — a classic griefing/DoS scenario.

### Likelihood Explanation
No special privileges are required. The attacker needs only:
1. A list of valid Hedera account IDs (publicly available via the mirror node itself or block explorers).
2. The ability to send HTTP GET requests at moderate volume.

Accounts with large numbers of token associations exist on mainnet and are easily identified. The attack is trivially scriptable, repeatable, and requires no on-chain transactions or funds.

### Recommendation
1. **Add a `LIMIT` to the CTE** matching the outer query limit, so the intermediate result set is bounded:
   ```sql
   with ta as (
     select *
     from token_account
     where account_id = $1
     order by token_id
     limit $2          -- pass the resolved limit here
   )
   ```
2. **Add application-level rate limiting** for unauthenticated callers on the `/api/v1/tokens` endpoint (e.g., via `express-rate-limit` keyed on `req.ip`).
3. **Reduce `statementTimeout`** for the read-replica pool used by the REST API to limit the maximum connection hold time for expensive queries.

### Proof of Concept
```bash
# Step 1: identify an account with many token associations
ACCOUNT="0.0.98"   # treasury account, typically has many associations

# Step 2: flood with rotating account IDs to bypass cache
for i in $(seq 1 500); do
  curl -s "https://<mirror-node>/api/v1/tokens?account.id=0.0.$i" &
done
wait
# Result: DB connection pool (max 10) saturated; concurrent legitimate
# requests to /api/v1/transactions, /api/v1/accounts, etc. begin timing out.
```

Each request forces the CTE `SELECT * FROM token_account WHERE account_id = $i ORDER BY token_id` to run without a limit, holding a DB connection for the full scan duration. With 10+ concurrent requests the pool is exhausted.