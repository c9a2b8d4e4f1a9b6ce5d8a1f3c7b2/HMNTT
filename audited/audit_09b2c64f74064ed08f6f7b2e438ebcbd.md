### Title
Unindexed ILIKE Full-Table Scan via `name` Filter Enables DB CPU Exhaustion (DoS)

### Summary
The `extractSqlFromTokenRequest()` function in `rest/tokens.js` wraps any user-supplied `name` filter value with `%` wildcards on both sides, producing `t.name ILIKE $1` with pattern `%value%`. Because no index on `token.name` supports this leading-wildcard pattern, every such query forces a full sequential scan of the token table. An unprivileged attacker sending concurrent requests with valid 3–100 byte name values can saturate DB CPU and degrade mirror node processing capacity.

### Finding Description

**Exact code path:**

`rest/tokens.js`, `extractSqlFromTokenRequest()`, line 176–178:

```js
if (filter.key === filterKeys.NAME) {
  conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
}
``` [1](#0-0) 

The user-supplied value is wrapped with `%…%`, making the pattern a leading-wildcard ILIKE. PostgreSQL cannot use a standard B-tree index on `token.name` for a leading-wildcard pattern; it must perform a sequential scan of the entire `token` table.

**Validation in `validateTokenQueryFilter()`** (line 333–335):

```js
case filterKeys.NAME:
  ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
  break;
``` [2](#0-1) 

The validator enforces a **minimum of 3 bytes** and a maximum of 100 bytes. The specific example `name=a` (1 byte) is rejected. However, any value of 3–100 bytes (e.g., `name=abc`) passes validation and reaches the ILIKE query unchanged.

**No index on `token.name`:** A search across all SQL migration files found no `CREATE INDEX` covering `token.name`, confirming every ILIKE query is a sequential scan.

**`statement_timeout` exists** (`rest/dbpool.js` line 15) but only terminates individual long-running queries after the timeout fires — it does not prevent many concurrent short-to-medium scans from collectively saturating DB CPU before any single one times out. [3](#0-2) 

**No application-layer rate limiting** was found in the REST handler path (`getTokensRequest`, `rest/tokens.js` lines 360–422). [4](#0-3) 

**Exploit flow:**
1. Attacker sends `GET /api/v1/tokens?name=abc` (3-byte minimum, passes validation).
2. `extractSqlFromTokenRequest` builds `WHERE t.name ILIKE $1` with `$1 = '%abc%'`.
3. PostgreSQL performs a full sequential scan of `token`.
4. Attacker fans out hundreds of concurrent identical requests.
5. DB CPU saturates; other mirror node queries (importer, other REST endpoints) are starved.

### Impact Explanation

A full sequential scan on a large `token` table is CPU- and I/O-intensive. With no rate limiting and no index, concurrent requests from a single unprivileged attacker can exhaust DB worker threads and CPU, causing query latency spikes across all mirror node components that share the same database. This matches the stated severity: degradation of ≥30% of network processing nodes without brute force (no authentication required, no special privileges, standard HTTP GET).

### Likelihood Explanation

- **No authentication required** — the `/api/v1/tokens` endpoint is public.
- **Minimum input constraint is trivially satisfied** — any 3-character ASCII string passes.
- **Easily automated** — a simple script with `curl` or `ab` (Apache Bench) can generate hundreds of concurrent requests.
- **Repeatable** — the attacker can sustain the attack indefinitely; there is no lockout or backoff mechanism in the code.

### Recommendation

1. **Add a `pg_trgm` GIN index** on `token.name` to support ILIKE with leading wildcards:
   ```sql
   CREATE INDEX idx_token_name_trgm ON token USING GIN (name gin_trgm_ops);
   ```
2. **Enforce a stricter minimum length** for the `name` filter (e.g., 5–8 bytes) to reduce the selectivity of broad patterns.
3. **Add application-layer rate limiting** (e.g., per-IP request rate cap) in the REST middleware for the `/api/v1/tokens` route.
4. **Set a short `statement_timeout`** specifically for ILIKE queries, or use a query cost guard (e.g., `SET LOCAL statement_timeout = '2s'` before executing name-filter queries).
5. **Consider disallowing the `name` filter without a more selective co-filter** (e.g., require `token.id` range or `type`).

### Proof of Concept

```bash
# Requires: curl, GNU parallel or xargs
# Send 200 concurrent ILIKE queries with minimum-length name value
seq 200 | xargs -P 200 -I{} \
  curl -s "https://<mirror-node-host>/api/v1/tokens?name=abc" -o /dev/null

# Monitor DB CPU on the mirror node host:
# watch -n1 "psql -c 'SELECT count(*), state FROM pg_stat_activity GROUP BY state;'"
# Expect: many 'active' sessions running sequential scans on token table,
# CPU near 100%, other queries timing out or queuing.
```

### Citations

**File:** rest/tokens.js (L176-178)
```javascript
    if (filter.key === filterKeys.NAME) {
      conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
    }
```

**File:** rest/tokens.js (L333-335)
```javascript
    case filterKeys.NAME:
      ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
      break;
```

**File:** rest/tokens.js (L360-397)
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

  const conditions = [];
  const getTokensSqlQuery = [tokensSelectQuery];
  const getTokenSqlParams = [];

  // if account.id filter is present join on token_account and filter dissociated tokens
  const accountId = req.query[filterKeys.ACCOUNT_ID];
  if (accountId) {
    conditions.push('ta.associated is true');
    getTokensSqlQuery.unshift(tokenAccountCte);
    getTokensSqlQuery.push(tokenAccountJoinQuery);
    getTokenSqlParams.push(EntityId.parseString(accountId, {paramName: filterKeys.ACCOUNT_ID}).getEncodedId());
  }

  // add join with entities table to sql query
  getTokensSqlQuery.push(entityIdJoinQuery);

  // build final sql query
  const {query, params, order, limit} = extractSqlFromTokenRequest(
    getTokensSqlQuery.join('\n'),
    getTokenSqlParams,
    filters,
    conditions
  );

  const rows = await getTokens(query, params);
```

**File:** rest/dbpool.js (L15-15)
```javascript
  statement_timeout: config.db.pool.statementTimeout,
```
