### Title
Unauthenticated DB Connection Pool Exhaustion via Concurrent NFT Multi-Union Queries

### Summary
The `GET /api/v1/accounts/:idOrAliasOrEvmAddress/nfts` endpoint is publicly accessible with no rate limiting. Any unauthenticated user can supply range filters (`token.id=gte:X&token.id=lte:Y&serialnumber=gt:A&serialnumber=lt:B`) that cause `extractNftMultiUnionQuery()` to build a 3-way `UNION ALL` SQL query with `LEFT JOIN` and `ORDER BY`, each holding a DB connection for up to the 20-second statement timeout. With a default pool of only 10 connections, 10 concurrent requests fully exhaust the pool, making the REST API unable to serve any gossiped transaction data until connections drain.

### Finding Description

**Route registration — no auth, no rate-limit middleware:** [1](#0-0) 

**Handler triggers multi-union query construction unconditionally:** [2](#0-1) 

**`extractNftMultiUnionQuery` builds lower/inner/upper filter sets from user-supplied params:** [3](#0-2) 

**`NftService.getQuery()` emits up to 3 `UNION ALL` subqueries, each with a `LEFT JOIN entity` and `ORDER BY token_id, serial_number`:** [4](#0-3) 

**Pool is capped at 10 connections by default; statement timeout is 20 seconds:** [5](#0-4) [6](#0-5) 

**The only existing "throttle" is in the `web3` module (contract calls), not the REST API:** [7](#0-6) 

The REST middleware stack (`authHandler`, `requestHandler`, `responseCacheHandler`, etc.) contains no per-IP or global request-rate limiter for this endpoint. [8](#0-7) 

The `maxRepeatedQueryParameters` guard (default 100) only rejects a single parameter repeated >100 times; the 3-union trigger requires only 4 distinct parameters (`token.id=gte:X`, `token.id=lte:Y`, `serialnumber=gt:A`, `serialnumber=lt:B`), well within the limit. [9](#0-8) 

### Impact Explanation

With 10 concurrent requests each holding a connection for up to 20 seconds, the entire REST API DB pool is exhausted. All subsequent REST API queries — including those serving gossiped transaction data — queue or fail with a connection-timeout error. The mirror node's REST serving layer becomes unavailable for the duration of the attack. The importer uses a separate DB user/pool, so gossip *ingestion* is unaffected, but *serving* of ingested data is fully blocked.

### Likelihood Explanation

No privileges, API keys, or special knowledge are required. A single attacker with a basic HTTP client (e.g., `curl`, `ab`, `wrk`) can issue 10 concurrent requests to any valid (or even invalid) account ID. The attack is trivially repeatable and scriptable, and the 20-second statement timeout means the attacker needs only ~0.5 requests/second per connection slot to maintain pool saturation indefinitely.

### Recommendation

1. **Add a request-rate limiter** (e.g., `express-rate-limit`) to the REST API, scoped per IP, before route handlers.
2. **Increase the default pool size** or add a connection-acquisition timeout that returns HTTP 503 instead of queuing indefinitely.
3. **Add a query-complexity budget** for the NFT endpoint: reject requests that would produce more than one UNION branch unless the account is authenticated.
4. **Consider a Redis-backed response cache** (already configurable but disabled by default) to serve repeated range queries without hitting the DB.

### Proof of Concept

```bash
# Exhaust the 10-connection pool with 10 concurrent range-filter requests
for i in $(seq 1 10); do
  curl -s "http://<mirror-node>:5551/api/v1/accounts/0.0.1001/nfts?\
token.id=gte:0.0.1&token.id=lte:0.0.999999&\
serialnumber=gt:1&serialnumber=lt:999999&limit=100" &
done
wait

# All subsequent REST API requests now fail or time out:
curl -v "http://<mirror-node>:5551/api/v1/transactions"
# Expected: connection timeout or HTTP 500 (pool exhausted)
```

### Citations

**File:** rest/routes/accountRoute.js (L15-15)
```javascript
router.getExt(getPath('nfts'), AccountController.getNftsByAccountId);
```

**File:** rest/controllers/accountController.js (L34-82)
```javascript
  extractNftMultiUnionQuery(filters, ownerAccountId) {
    const bounds = {
      primary: new Bound(filterKeys.TOKEN_ID, 'token_id'),
      secondary: new Bound(filterKeys.SERIAL_NUMBER, 'serial_number'),
    };
    let limit = defaultLimit;
    let order = orderFilterValues.DESC;
    const spenderIdFilters = [];
    const spenderIdInFilters = [];

    for (const filter of filters) {
      switch (filter.key) {
        case filterKeys.SERIAL_NUMBER:
          bounds.secondary.parse(filter);
          break;
        case filterKeys.TOKEN_ID:
          bounds.primary.parse(filter);
          break;
        case filterKeys.LIMIT:
          limit = filter.value;
          break;
        case filterKeys.ORDER:
          order = filter.value;
          break;
        case filterKeys.SPENDER_ID:
          filter.operator === utils.opsMap.eq ? spenderIdInFilters.push(filter) : spenderIdFilters.push(filter);
          break;
        default:
          break;
      }
    }

    this.validateFilters(bounds, spenderIdFilters);

    const lower = this.getLowerFilters(bounds);
    const inner = this.getInnerFilters(bounds);
    const upper = this.getUpperFilters(bounds);
    return {
      bounds,
      lower,
      inner,
      upper,
      order,
      ownerAccountId,
      limit,
      spenderIdInFilters,
      spenderIdFilters,
    };
  }
```

**File:** rest/controllers/accountController.js (L90-94)
```javascript
  getNftsByAccountId = async (req, res) => {
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const filters = utils.buildAndValidateFilters(req.query, acceptedNftAccountParameters);
    const query = this.extractNftMultiUnionQuery(filters, accountId);
    const nonFungibleTokens = await NftService.getNfts(query);
```

**File:** rest/service/nftService.js (L93-123)
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
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-20)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
```

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
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
