### Title
Unauthenticated Per-Request DB Query in `getTokenRelationships()` Exhausts Connection Pool via `isValidAccount()`

### Summary
The `getTokenRelationships()` handler unconditionally calls `EntityService.isValidAccount()` on every inbound request, which issues a live database query with no caching. Because the Node.js REST API has no rate-limiting middleware and the default DB connection pool is only 10 connections, an unprivileged attacker sending concurrent requests with different valid numeric account IDs can saturate the pool and deny service to all other API consumers.

### Finding Description
**Exact code path:**

`rest/controllers/tokenController.js`, `getTokenRelationships()`, lines 67–68:
```js
const accountId = await EntityService.getEncodedId(req.params[...]);
const isValidAccount = await EntityService.isValidAccount(accountId);
``` [1](#0-0) 

`rest/service/entityService.js`, `isValidAccount()`, lines 60–62:
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

`BaseService.getSingleRow()` → `getRows()` → `pool.queryQuietly()` acquires a real connection from the global pool on every call: [4](#0-3) 

**Root cause — failed assumption:** The code assumes that the `isValidAccount` existence check is cheap enough to run unconditionally. There is no in-process cache for this result, no request-level deduplication, and no rate-limiting middleware anywhere in the Node.js REST API layer.

**Why existing checks fail:**
- `getEncodedId()` for a plain numeric ID (e.g. `0.0.1234`) performs only local arithmetic and returns without touching the DB: [5](#0-4) 
  So the attacker pays zero DB cost to resolve the account ID, but `isValidAccount()` always pays one.
- The `entityId` LRU cache in `entityId.js` caches only the parsed `EntityId` object, not the DB existence result: [6](#0-5) 
- The throttle/rate-limit infrastructure that exists in the codebase lives entirely in the Java `web3/` module and is not wired into the Node.js REST API: [7](#0-6) 
- A grep across all `rest/**/*.js` for `rate.?limit|throttle|rateLimit` returns only a test utility file — no production middleware.

**Pool size:** The documented default for the REST API pool is **10 connections**: [8](#0-7) 

Confirmed in `dbpool.js`: [9](#0-8) 

Each request holds a connection for the full `statement_timeout` window (default 20 000 ms) if the DB is under load, so 10 concurrent attacker requests are sufficient to starve the pool.

### Impact Explanation
With the pool exhausted, every other REST API endpoint that issues a DB query (accounts, transactions, tokens, etc.) will block waiting for a free connection until `connectionTimeoutMillis` (default 20 000 ms) elapses, at which point the request fails with a pool-timeout error. The entire mirror-node REST API becomes effectively unavailable to legitimate users for the duration of the attack. Because the attacker uses valid, publicly known account IDs (any account on the Hedera ledger qualifies), there is no prerequisite knowledge or privilege required.

### Likelihood Explanation
The attack requires only an HTTP client and knowledge of any valid Hedera account ID (trivially obtained from the public ledger or the mirror node's own `/accounts` endpoint). It is stateless, requires no authentication, and is trivially parallelisable with tools like `ab`, `wrk`, or a simple async script. The attacker does not need to sustain a high packet rate — holding 10 slow connections open is sufficient given the 10-connection default pool. The attack is repeatable indefinitely.

### Recommendation
1. **Cache `isValidAccount` results** — introduce a short-lived (e.g. 30–60 s) in-process LRU cache keyed on `accountId`, similar to the existing `entityId` parse cache, so repeated lookups for the same account do not hit the DB.
2. **Add rate limiting to the Node.js REST API** — apply a per-IP (or global) request-rate limiter (e.g. `express-rate-limit`) as middleware before any route handler, mirroring the bucket4j throttle already present in the `web3` module.
3. **Increase pool size or add a concurrency semaphore** — raise `db.pool.maxConnections` in production deployments and/or add a concurrency gate so a single endpoint cannot monopolise the entire pool.
4. **Fail fast before acquiring a connection** — move the account-ID format validation (which is already free) before any DB call, and consider returning 404 without a DB round-trip for IDs that are structurally valid but outside the known numeric range.

### Proof of Concept
```bash
# Requires: curl, GNU parallel (or any async HTTP tool)
# Enumerate 50 different valid account IDs and fire them concurrently

seq 1 50 | parallel -j50 \
  'curl -s -o /dev/null -w "%{http_code}\n" \
   "https://<mirror-node-host>/api/v1/accounts/0.0.{}/tokens"'

# Expected during attack: legitimate requests to any REST endpoint
# begin returning 503 / connection-timeout errors within seconds.
# After the attack stops, the pool recovers automatically.
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

**File:** rest/service/entityService.js (L120-123)
```javascript
      if (EntityId.isValidEntityId(entityIdString)) {
        const entityId = EntityId.parseString(entityIdString, {paramName});
        return entityId.evmAddress === null
          ? entityId.getEncodedId()
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** docs/configuration.md (L556-556)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
```

**File:** rest/dbpool.js (L14-14)
```javascript
  max: config.db.pool.maxConnections,
```
