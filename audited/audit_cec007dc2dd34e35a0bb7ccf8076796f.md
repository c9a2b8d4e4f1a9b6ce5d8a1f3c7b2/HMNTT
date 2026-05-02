### Title
Unauthenticated Full-Table ILIKE Scan via Name Filter Disables Pagination and Holds DB Connection

### Summary
In `rest/tokens.js`, the `getTokensRequest()` function unconditionally disables cursor-based pagination when the `name` query parameter is present, while still executing a `t.name ILIKE '%value%'` query that requires a full sequential table scan. Any unauthenticated caller can combine `name=<3-100 char string>` with `limit=100` (the configured maximum) to trigger the most expensive possible single-response query with no next-link, holding a database connection for the entire scan duration. Repeated concurrent requests can exhaust the connection pool.

### Finding Description

**Pagination disabled unconditionally on name filter:** [1](#0-0) 

`hasNameParam` being truthy forces `nextLink = null` regardless of how many rows exist in the table. There is no fallback to cursor pagination even when the result set is large.

**ILIKE with leading wildcard forces full sequential scan:** [2](#0-1) 

The pattern `'%' + filter.value + '%'` means PostgreSQL cannot use any B-tree index on `t.name`. The engine must read every row in the `token` table to evaluate the predicate.

**Limit is applied at SQL level but does not bound the scan cost:** [3](#0-2) 

`LIMIT 100` (the configured max) tells PostgreSQL to stop *returning* rows after 100 matches, but the engine still scans forward through the table until it accumulates 100 hits. On a large token table with sparse matches, this can mean scanning millions of rows before the query returns.

**Validation only checks positive-long, does not cap at max within this path:** [4](#0-3) 

`isPositiveLong` accepts any positive integer. The cap to `responseLimit.max` (100) is enforced by `getLimitParamValue` inside `parseLimitAndOrderParams`, but `getTokensRequest` routes through `buildAndValidateFilters` + `validateTokenQueryFilter` instead, so the effective cap depends entirely on whether `buildAndValidateFilters` internally calls `getLimitParamValue` for the LIMIT key.

**No authentication required:** [5](#0-4) 

The only guards are mutual-exclusion checks (`name` cannot coexist with `token.id` or `account.id`). There is no authentication, no rate-limit, and no query-cost guard.

### Impact Explanation

Each request with `?name=abc&limit=100` occupies one database connection from the pool for the full duration of the sequential scan. The configured pool has a finite `maxConnections`. An attacker sending a modest number of concurrent requests (e.g., 20–50) can saturate the pool, causing all subsequent queries—including those serving legitimate users and internal health checks—to queue or time out. Because the mirror node is a read-only API, this does not directly alter ledger state, but it can render the REST API unavailable, which is a denial-of-service against the network's data-access layer.

### Likelihood Explanation

The exploit requires zero privileges, zero tokens, and zero knowledge beyond the public OpenAPI spec. The `name` parameter is documented. The attack is trivially scriptable with `curl` or any HTTP client. It is repeatable indefinitely because there is no per-IP or per-user rate limit enforced at the application layer in this code path. A single attacker with a modest number of concurrent connections can sustain the attack.

### Recommendation

1. **Re-enable pagination for name-filter queries** or enforce a hard upper bound on the result set that is lower than the general `limit.max` when `name` is present.
2. **Add a GIN/trigram index** (`pg_trgm`) on `token.name` so that `ILIKE '%value%'` can use an index rather than a sequential scan.
3. **Enforce a statement timeout** at the PostgreSQL session level for REST API connections (e.g., `SET statement_timeout = '5s'`) so runaway scans are killed automatically.
4. **Apply rate limiting** at the API gateway or middleware layer, keyed on source IP, for endpoints that accept free-text search parameters.
5. **Cap the limit within `validateTokenQueryFilter`** (or within `buildAndValidateFilters`) to `responseLimit.max` explicitly, rather than relying on `isPositiveLong` alone.

### Proof of Concept

```bash
# Single request – triggers full sequential scan, no pagination link returned
curl -s "https://<mirror-node>/api/v1/tokens?name=abc&limit=100" | jq '.links'
# Expected: {"next": null}  ← pagination permanently disabled

# DoS – saturate the DB connection pool with concurrent scans
for i in $(seq 1 50); do
  curl -s "https://<mirror-node>/api/v1/tokens?name=abc&limit=100" &
done
wait
# Subsequent legitimate requests will queue or return 503/timeout
```

Relevant code path:
- `rest/tokens.js` → `getTokensRequest()` lines 360–422
- `rest/tokens.js` → `extractSqlFromTokenRequest()` lines 164–214, specifically line 177 (ILIKE) and line 210 (LIMIT)
- `rest/tokens.js` → pagination gate lines 404–414

### Citations

**File:** rest/tokens.js (L176-178)
```javascript
    if (filter.key === filterKeys.NAME) {
      conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
    }
```

**File:** rest/tokens.js (L209-211)
```javascript
  const orderQuery = `order by ${sqlQueryColumns.TOKEN_ID} ${order}`;
  const limitQuery = `limit $${params.push(limit)}`;
  query = [query, whereQuery, orderQuery, limitQuery].filter((q) => q !== '').join('\n');
```

**File:** rest/tokens.js (L330-332)
```javascript
    case filterKeys.LIMIT:
      ret = utils.isPositiveLong(val);
      break;
```

**File:** rest/tokens.js (L360-371)
```javascript
const getTokensRequest = async (req, res) => {
  const hasNameParam = !!req.query[filterKeys.NAME];
  if (hasNameParam && req.query[filterKeys.TOKEN_ID]) {
    throw new InvalidArgumentError('token.id and name can not be used together. Use a more specific name instead.');
  }

  if (hasNameParam && req.query[filterKeys.ACCOUNT_ID]) {
    throw new InvalidArgumentError('account.id and name cannot be used together');
  }
  // validate filters, use custom check for tokens until validateAndParseFilters is optimized to handle
  // per resource unique param names
  const filters = utils.buildAndValidateFilters(req.query, acceptedTokenParameters, validateTokenQueryFilter);
```

**File:** rest/tokens.js (L404-414)
```javascript
  const lastTokenId = tokens.length > 0 ? tokens[tokens.length - 1].token_id : null;
  const nextLink = hasNameParam
    ? null
    : utils.getPaginationLink(
        req,
        tokens.length !== limit,
        {
          [filterKeys.TOKEN_ID]: lastTokenId,
        },
        order
      );
```
