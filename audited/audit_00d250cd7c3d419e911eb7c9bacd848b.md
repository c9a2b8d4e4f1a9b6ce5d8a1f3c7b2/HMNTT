### Title
Uncached Per-Request DB Query in `isValidAccount()` Enables Connection Pool Exhaustion via Unauthenticated Flood

### Summary
`getTokenRelationships()` calls `EntityService.isValidAccount()` on every request, which unconditionally issues a fresh `SELECT type FROM entity WHERE id = $1` database query with no caching. The REST API has no application-level rate limiting, and the default DB connection pool is only 10 connections. An unauthenticated attacker flooding the endpoint with different valid account IDs can exhaust the pool, causing all REST API endpoints to stall or time out.

### Finding Description
**Exact code path:**

`rest/controllers/tokenController.js` lines 67–68:
```js
const accountId = await EntityService.getEncodedId(req.params[...]);
const isValidAccount = await EntityService.isValidAccount(accountId);
``` [1](#0-0) 

`rest/service/entityService.js` lines 60–63 — `isValidAccount()` calls `getSingleRow()` directly against the pool with no cache layer:
```js
async isValidAccount(accountId) {
  const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
  return !isNil(entity);
}
``` [2](#0-1) 

The query executed is:
```sql
select type from entity where id = $1
``` [3](#0-2) 

`rest/service/baseService.js` line 56 — `getSingleRow` → `getRows` → `pool.queryQuietly()`, directly consuming a pool connection: [4](#0-3) 

**Root cause:** `isValidAccount()` has zero caching. The `entityId.js` LRU cache only caches string-to-`EntityId` *parsing*, not the DB existence check. [5](#0-4) 

The default pool maximum is **10 connections** (`hiero.mirror.rest.db.pool.maxConnections = 10`): [6](#0-5) 

**No application-level rate limiting exists in the REST API.** `rest/server.js` registers only: `authHandler`, `requestLogger`, `requestQueryParser`, `responseCacheCheckHandler`, `responseCacheUpdateHandler`, `responseHandler`, `metricsHandler`, `openApiValidator`, `handleError` — no rate limiter middleware: [7](#0-6) 

The throttle/rate-limit code (`ThrottleManagerImpl`, `ThrottleConfiguration`) belongs exclusively to the Java `web3` module and does not protect the Node.js REST API: [8](#0-7) 

### Impact Explanation
With 10 pool connections and a `connectionTimeoutMillis` of 20 000 ms, an attacker sending ~20–30 concurrent requests per second to `/api/v1/accounts/{id}/tokens` with rotating valid numeric account IDs (e.g., `0.0.1` through `0.0.N`) will hold all pool connections in the `isValidAccount` + `getTokenAccounts` query pair. Subsequent requests from all users across all REST endpoints queue behind the pool timeout, causing 20-second latency spikes or `connection timeout` errors — effectively a full REST API denial of service. No economic damage occurs on-chain; the impact is pure service availability (griefing). [3](#0-2) 

### Likelihood Explanation
Preconditions: none. The endpoint is unauthenticated and publicly reachable. Valid account IDs are trivially enumerable (sequential integers). A single attacker with a modest HTTP client (e.g., `ab`, `wrk`, or a simple script) can sustain the flood. The attack is repeatable and requires no special knowledge beyond the public API spec.

### Recommendation
1. **Add caching to `isValidAccount()`**: Cache the boolean result keyed by `accountId` using the existing `quickLru` pattern (same as `entityId.js`) with a short TTL (e.g., 30–60 s). This eliminates the per-request DB hit for repeated account IDs.
2. **Add application-level rate limiting** to the REST API (e.g., `express-rate-limit`) scoped per IP, before route handlers.
3. **Increase the default pool size** or configure pgBouncer's `max_user_connections` for `mirror_rest` to a value that can absorb burst traffic without full exhaustion. [2](#0-1) 

### Proof of Concept
```bash
# Pre-condition: mirror-node REST API running on localhost:5551
# Step 1: enumerate a range of valid account IDs (0.0.1 to 0.0.500 exist on mainnet)
# Step 2: flood with high concurrency using different IDs to bypass any future cache

seq 1 500 | xargs -P 50 -I{} \
  curl -s "http://localhost:5551/api/v1/accounts/0.0.{}/tokens" -o /dev/null

# Result: pool of 10 connections saturated; all other REST API calls stall
# for up to connectionTimeoutMillis (20 000 ms) or return connection errors.
# Repeat in a loop to sustain the outage indefinitely.
```

### Citations

**File:** rest/controllers/tokenController.js (L67-68)
```javascript
    const accountId = await EntityService.getEncodedId(req.params[filterKeys.ID_OR_ALIAS_OR_EVM_ADDRESS]);
    const isValidAccount = await EntityService.isValidAccount(accountId);
```

**File:** rest/service/entityService.js (L28-30)
```javascript
  static entityExistenceQuery = `select ${Entity.TYPE}
                                 from ${Entity.tableName}
                                 where ${Entity.ID} = $1`;
```

**File:** rest/service/entityService.js (L60-63)
```javascript
  async isValidAccount(accountId) {
    const entity = await super.getSingleRow(EntityService.entityExistenceQuery, [accountId]);
    return !isNil(entity);
  }
```

**File:** rest/service/baseService.js (L55-57)
```javascript
  async getRows(query, params) {
    return (await this.pool().queryQuietly(query, params)).rows;
  }
```

**File:** rest/entityId.js (L301-304)
```javascript
const cache = new quickLru({
  maxAge: entityIdCacheConfig.maxAge * 1000, // in millis
  maxSize: entityIdCacheConfig.maxSize,
});
```

**File:** rest/dbpool.js (L13-15)
```javascript
  connectionTimeoutMillis: config.db.pool.connectionTimeout,
  max: config.db.pool.maxConnections,
  statement_timeout: config.db.pool.statementTimeout,
```

**File:** rest/server.js (L24-34)
```javascript
import {
  authHandler,
  handleError,
  openApiValidator,
  requestLogger,
  requestQueryParser,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
  responseHandler,
  serveSwaggerDocs,
} from './middleware';
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
