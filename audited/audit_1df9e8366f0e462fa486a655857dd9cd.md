### Title
Unauthenticated Per-Request DB Query Flood via Alias Resolution in `getTokenRelationships()`

### Summary
The `getTokenRelationships()` handler in `rest/controllers/tokenController.js` resolves the account identifier on every request by issuing two uncached database queries — one alias lookup and one existence check — with no rate limiting applied to unauthenticated callers. An attacker can flood the endpoint with syntactically valid account aliases, causing each concurrent request to consume a DB connection, saturating the pool and denying service to all other API consumers.

### Finding Description

**Exact code path:**

`getTokenRelationships()` at `rest/controllers/tokenController.js` lines 67–68 unconditionally calls two `EntityService` methods per request:

```js
// tokenController.js:67-68
const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
const isValidAccount = await EntityService.isValidAccount(accountId);
```

`getEncodedId()` at `rest/service/entityService.js` lines 125–126 detects a valid alias format and calls `getAccountIdFromAlias()` → `getAccountFromAlias()`:

```js
// entityService.js:125-126
} else if (AccountAlias.isValid(entityIdString)) {
  return await this.getAccountIdFromAlias(AccountAlias.fromString(entityIdString), requireResult);
```

`getAccountFromAlias()` at `rest/service/entityService.js` lines 42–53 issues a raw SQL query with no caching:

```js
// entityService.js:43
const rows = await super.getRows(EntityService.entityFromAliasQuery, [accountAlias.alias]);
```

`isValidAccount()` at `rest/service/entityService.js` lines 60–62 issues a second raw SQL query:

```js
// entityService.js:61
const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
```

`BaseService.getRows()` at `rest/service/baseService.js` lines 55–57 goes directly to the DB pool with no cache layer:

```js
// baseService.js:56
return (await this.pool().queryQuietly(query, params)).rows;
```

**Root cause:** No result caching exists anywhere in the alias-resolution path. Unlike `transactions.js` line 705 which uses `cache.get()`, `EntityService` has no equivalent. The `authHandler.js` middleware only sets a response-row limit for authenticated users — it does not rate-limit or block unauthenticated request volume. No IP-based throttle or request-rate limiter is present in the middleware stack.

**Why existing checks fail:** The `authHandler` at `rest/middleware/authHandler.js` lines 18–20 simply returns (allows the request through) when no `Authorization` header is present — it imposes zero restriction on unauthenticated callers. The `requestQueryParser` only canonicalizes query parameters. There is no middleware that counts or throttles requests per IP or per time window.

### Impact Explanation
An attacker with no credentials can exhaust the PostgreSQL connection pool by sending a high volume of concurrent requests to `/api/v1/accounts/{alias}/tokens`. Each request consumes two DB connections (or two sequential pool checkouts) for alias resolution and existence validation. Once the pool is saturated, all other API endpoints that require DB access — transactions, balances, contracts, etc. — will queue or fail, constituting a full denial of service for all API consumers. This affects a public-facing REST API for a network with ≥25% market capitalization, making the blast radius network-wide.

### Likelihood Explanation
The attack requires no authentication, no special knowledge, and no on-chain funds. Any attacker with a script and a valid base32 alias string (the format is publicly documented) can trigger it. The attack is trivially repeatable and automatable with standard HTTP load tools (e.g., `wrk`, `ab`, `hey`). The alias format is validated client-side before the DB query is issued, so even non-existent aliases (which return `null` from `getAccountFromAlias`) still consume a full DB round-trip. The attacker can use a single alias string repeated across all requests — no enumeration needed.

### Recommendation
1. **Add a result cache** in `EntityService.getAccountFromAlias()` and `EntityService.isValidAccount()` keyed on the alias/accountId, with a short TTL (e.g., 5–30 seconds). A simple in-process LRU cache (e.g., `lru-cache`) would absorb repeated lookups for the same alias.
2. **Add IP-based rate limiting** middleware (e.g., `express-rate-limit`) applied globally before route handlers, with a low burst limit for unauthenticated callers.
3. **Merge the two DB queries** into one: a single query that resolves the alias and checks existence simultaneously eliminates one of the two DB round-trips per request.
4. **Short-circuit on alias miss**: cache negative results (alias not found) to prevent repeated DB hits for the same non-existent alias.

### Proof of Concept

**Preconditions:** Public mirror node REST API accessible. No credentials required.

**Steps:**

```bash
# Generate a syntactically valid base32 alias (does not need to exist in DB)
ALIAS="KGNABD5L3ZGSRVUCSPDR7TONZSRY3D5OMEBKQMVTD2AC6JL72HMQ"

# Flood the endpoint with concurrent requests
# Each request triggers 2 uncached DB queries
hey -n 10000 -c 200 \
  "https://<mirror-node-host>/api/v1/accounts/${ALIAS}/tokens"
```

**Result:** DB connection pool saturates. Subsequent requests to any endpoint (e.g., `/api/v1/transactions`) begin timing out or returning 500 errors as the pool queue overflows. The attacker pays zero cost (no auth, no on-chain activity) while the service is degraded for all legitimate users.