### Title
Unauthenticated High-Concurrency NFT Query Exhausts REST API Database Connection Pool

### Summary
The `getNftsByAccountId()` handler in `rest/controllers/accountController.js` accepts `limit=100` (the configured maximum) from any unauthenticated caller with no application-level rate limiting. The REST API's database pool is capped at 10 connections with a 20-second statement timeout, meaning only 10 concurrent requests are needed to fully saturate the pool and queue-block all other REST API consumers. Sustained high-concurrency flooding across many account IDs degrades the entire mirror-node REST API service.

### Finding Description
**Code path:**

`GET /api/v1/accounts/:id/nfts?limit=100&order=desc` → `getNftsByAccountId()` (accountController.js:90-103) → `utils.buildAndValidateFilters()` → `NftService.getNfts()` (nftService.js:134-138) → `pool.queryQuietly(sqlQuery, params)`.

**Root cause – no rate limiting on the REST API:**

The Node.js REST API has zero application-level rate limiting middleware. The web3 Java service has `ThrottleManagerImpl` with a `rateLimitBucket`, and the Rosetta Helm chart configures Traefik `rateLimit`, but neither applies to the Node.js REST API. No per-IP, per-endpoint, or global request throttle exists in the REST API codebase.

**Limit enforcement is correct but insufficient:**

`getLimitParamValue()` (utils.js:544-553) caps the limit at `responseLimit.max = 100` for unauthenticated callers. This is working as designed, but it means every unauthenticated request may legitimately request 100 rows.

**The generated SQL query (nftService.js:108-118) with no token/serial filters:**
```sql
SELECT account_id, created_timestamp, ...
FROM nft
LEFT JOIN entity e ON e.id = nft.token_id
WHERE account_id = $1
ORDER BY token_id DESC, serial_number DESC
LIMIT $2   -- $2 = 100
```
With no `token_id` or `serial_number` bounds, `lower`/`inner`/`upper` are all empty, producing a single subquery that must sort and return up to 100 rows per account. For accounts holding many NFTs this requires a non-trivial index scan plus a sort.

**Database pool is the hard ceiling:**

`dbpool.js` (lines 7-16) configures `max: config.db.pool.maxConnections` (default **10**) and `statement_timeout: 20000` ms. With only 10 connections, 10 simultaneous slow queries fully saturate the pool. All subsequent requests block in the `pg` queue until a connection is released (up to 20 s per query × 10 slots = up to 200 s of queued backlog per wave).

**Why existing checks fail:**

| Check | Value | Why insufficient |
|---|---|---|
| `statementTimeout` | 20 000 ms | Attacker re-issues requests immediately; pool stays saturated |
| `maxConnections` | 10 | Trivially saturated with 10 concurrent requests |
| Limit cap | 100 rows | Legitimate cap, but still allows maximum-cost queries |
| No rate limiting | — | Nothing prevents a single IP from holding all 10 slots |

### Impact Explanation
The REST API is the primary public interface of the mirror node. Saturating its 10-connection pool blocks **all** REST endpoints (accounts, transactions, tokens, NFTs, etc.) for all users. Because the pool is shared across every handler, a targeted flood of `/accounts/:id/nfts?limit=100` requests causes cascading timeouts on unrelated endpoints. This constitutes a full degradation of the mirror node's REST processing capacity, meeting the ≥30% network-processing-node impact threshold for the mirror node service tier.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond a list of valid account IDs (publicly enumerable from the same API), and no brute force. A single attacker with a modest script sending 10–20 concurrent HTTP requests can sustain pool saturation indefinitely. The attack is trivially repeatable, cheap to automate, and leaves no authentication trail.

### Recommendation
1. **Add application-level rate limiting** to the Node.js REST API (e.g., `express-rate-limit` or Traefik middleware) — at minimum per-IP, ideally per-endpoint.
2. **Increase `maxConnections`** or introduce a request queue with a maximum depth and a fast-fail 429 response when the queue is full.
3. **Add a per-request concurrency limiter** (e.g., `express-slow-down` or a semaphore) specifically for expensive paginated endpoints.
4. **Reduce `statementTimeout`** for read-only NFT queries to limit how long each connection is held.
5. Consider requiring a minimum filter (e.g., `token.id`) when `limit` is at maximum to prevent unbounded scans.

### Proof of Concept
```bash
# Enumerate a valid account ID (e.g., 0.0.1234)
# Then saturate the pool with 15 concurrent max-limit requests:

for i in $(seq 1 15); do
  curl -s "https://<mirror-node>/api/v1/accounts/0.0.$((RANDOM % 5000 + 1000))/nfts?limit=100&order=desc" &
done
wait

# Immediately probe an unrelated endpoint:
time curl "https://<mirror-node>/api/v1/transactions?limit=1"
# Expected: response time >> normal baseline, or HTTP 500/timeout
# Repeat in a loop to sustain saturation
```

Preconditions: network access to the REST API, knowledge of any valid account IDs (obtainable from `GET /api/v1/accounts`). No authentication required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/controllers/accountController.js (L90-103)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
    const query = this.extractNftMultiUnionQuery(filters, accountId);
    const nonFungibleTokens = await NftService.getNfts(query);
    const nfts = nonFungibleTokens.map((nft) => new NftViewModel(nft));

    res.locals[responseDataLabel] = {
      nfts,
      links: {
        next: this.getPaginationLink(req, nfts, query.bounds, query.limit, query.order),
      },
    };
  };
```

**File:** rest/service/nftService.js (L107-126)
```javascript
    let sqlQuery;
    if (subQueries.length === 0) {
      // if all three filters are empty, the subqueries will be empty too, just create the query with empty filters
      sqlQuery = this.getSubQuery(
        [],
        params,
        accountIdCondition,
        limitClause,
        orderClause,
        spenderIdInFilters,
        spenderIdFilters
      );
    } else if (subQueries.length === 1) {
      sqlQuery = subQueries[0];
    } else {
      sqlQuery = [subQueries.map((q) => `(${q})`).join('\nunion all\n'), orderClause, limitClause].join('\n');
    }

    return {sqlQuery, params};
  }
```

**File:** rest/dbpool.js (L7-16)
```javascript
const poolConfig = {
  user: config.db.username,
  host: config.db.host,
  database: config.db.name,
  password: config.db.password,
  port: config.db.port,
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
};
```

**File:** rest/utils.js (L544-553)
```javascript
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```
