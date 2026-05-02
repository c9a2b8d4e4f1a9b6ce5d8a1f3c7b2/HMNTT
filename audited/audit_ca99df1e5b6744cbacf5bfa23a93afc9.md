### Title
Unauthenticated Full-Table ILIKE Scan DoS via `GET /tokens?name=` — No Rate Limiting, No Cursor Bound

### Summary
The `getTokensRequest()` handler in `rest/tokens.js` translates any `name` query parameter into a PostgreSQL `ILIKE '%value%'` predicate with a leading wildcard, which forces a full sequential scan of the `token` table on every request. Pagination is unconditionally suppressed (`nextLink = null`) when `hasNameParam` is true, and no rate limiting exists on this endpoint for unauthenticated callers. An attacker can flood the endpoint with repeated requests, each triggering a full table scan, causing sustained database CPU and I/O exhaustion that degrades the mirror node's ability to serve other requests and ingest new data.

### Finding Description
**Exact code path:**

In `rest/tokens.js`, `extractSqlFromTokenRequest()` at line 177:
```js
conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
```
The `%` prefix on the value means PostgreSQL cannot use any B-tree index on `token.name`. Every invocation performs a sequential scan of the entire `token` table regardless of the `LIMIT` clause appended at line 210. The `LIMIT` only caps the number of rows returned; it does not bound the scan range — PostgreSQL must evaluate the predicate against every row before it can stop.

In `getTokensRequest()` at lines 405–406:
```js
const nextLink = hasNameParam
  ? null
  : utils.getPaginationLink(...)
```
Pagination is disabled entirely for name searches. There is no cursor-based mechanism to resume from a known position, so every request is a fresh unbounded scan.

**Validation constraints** (line 334):
```js
ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
```
The minimum of 3 bytes is trivially satisfied. The maximum of 100 bytes does not reduce scan cost.

**Rate limiting:** The throttling infrastructure found in the codebase (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` module (contract calls). No equivalent rate limiter is applied to the REST API's `/api/v1/tokens` endpoint. The `getEffectiveMaxLimit()` in `utils.js` (line 533) only caps the number of rows returned, not the request rate.

**Default/max limit** (from config): default=25, max=100. These cap output rows, not scan cost.

### Impact Explanation
A sustained flood of `GET /api/v1/tokens?name=abc` requests causes repeated full sequential scans of the `token` table. On a production Hedera mirror node with millions of token records, each scan is a significant I/O and CPU operation. Concurrent scans exhaust the database connection pool and degrade query throughput across all endpoints. The mirror node's transaction ingestion pipeline shares the same database, so sustained load can delay the node's ability to process and serve newly confirmed transactions. This is a denial-of-service against the mirror node infrastructure, not the Hedera consensus layer directly.

### Likelihood Explanation
No authentication, no API key, no rate limit, and no CAPTCHA is required. The minimum name length of 3 characters is trivially satisfied. The attack is fully automatable with a single `curl` loop or any HTTP load tool. Any external actor with network access to the mirror node's REST API can execute this. The attack is repeatable indefinitely and requires no special knowledge beyond reading the public API documentation.

### Recommendation
1. **Eliminate the leading wildcard**: Change the ILIKE pattern from `'%' + value + '%'` to `value + '%'` (prefix-only), which allows a `text_pattern_ops` B-tree index or a trigram (`pg_trgm`) GIN index to be used.
2. **Add a GIN trigram index** on `token.name` (`CREATE INDEX ON token USING gin(name gin_trgm_ops)`) if substring matching must be preserved.
3. **Apply rate limiting** to the `/api/v1/tokens` endpoint, consistent with the throttling already implemented for the `web3` module.
4. **Enforce a query timeout** at the DB level for this query class (a `statement_timeout` per role or per query).
5. **Require a minimum name length** longer than 3 bytes if full substring search is retained, to reduce the attacker's ability to match large fractions of the table.

### Proof of Concept
```bash
# No authentication required. Runs indefinitely, each request triggers a full table scan.
while true; do
  curl -s "https://<mirror-node-host>/api/v1/tokens?name=abc" > /dev/null &
done
# Observe: DB CPU spikes to 100%, query latency for all endpoints increases,
# mirror node ingestion lag grows.
```

Preconditions: Network access to the mirror node REST API (publicly exposed in production).
Trigger: `GET /api/v1/tokens?name=<any 3+ byte string>` with no credentials.
Result: Each request executes `SELECT ... FROM token t JOIN entity e ... WHERE t.name ILIKE '%abc%' ... LIMIT 25` as a full sequential scan; concurrent requests saturate the database. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/tokens.js (L176-178)
```javascript
    if (filter.key === filterKeys.NAME) {
      conditions.push(`t.name ILIKE $${params.push('%' + filter.value + '%')}`);
    }
```

**File:** rest/tokens.js (L208-211)
```javascript
  const whereQuery = conditions.length !== 0 ? `where ${conditions.join(' and ')}` : '';
  const orderQuery = `order by ${sqlQueryColumns.TOKEN_ID} ${order}`;
  const limitQuery = `limit $${params.push(limit)}`;
  query = [query, whereQuery, orderQuery, limitQuery].filter((q) => q !== '').join('\n');
```

**File:** rest/tokens.js (L333-335)
```javascript
    case filterKeys.NAME:
      ret = op === queryParamOperators.eq && utils.isByteRange(val, 3, 100);
      break;
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
