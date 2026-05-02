### Title
DB Connection Pool Exhaustion via Unauthenticated High-Frequency Requests to `getBlocks()`

### Summary
`getBlocks()` in `rest/controllers/blockController.js` issues a live database query on every invocation with no in-function caching and no rate limiting in the REST API layer. The Redis-based response cache that could mitigate this is **disabled by default** (`cache.response.enabled = false`). The default DB connection pool is capped at 10 connections, so a flood of identical unauthenticated requests can exhaust the pool and deny service to all REST API consumers.

### Finding Description
**Exact code path:**

`rest/controllers/blockController.js`, `getBlocks()`, lines 101–112:
```js
getBlocks = async (req, res) => {
  const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
  const formattedFilters = this.extractSqlFromBlockFilters(filters);
  const blocks = await RecordFileService.getBlocks(formattedFilters); // unconditional DB call
  ...
};
``` [1](#0-0) 

**Root cause — response cache disabled by default:**

`rest/server.js` line 54 gates the cache on both `config.cache.response.enabled` AND `config.redis.enabled`:
```js
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
``` [2](#0-1) 

The cache check middleware is only registered when `applicationCacheEnabled` is true:
```js
if (applicationCacheEnabled) {
  app.useExt(responseCacheCheckHandler);
}
``` [3](#0-2) 

The documented default for `hiero.mirror.rest.cache.response.enabled` is **`false`**: [4](#0-3) 

**Root cause — no rate limiting in the REST API:**

A `grep` across all `rest/**/*.js` files for `rateLimit`, `rateLimiter`, or `express-rate-limit` returns zero hits in production code. The throttling that exists (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` Java service and is scoped to `/contracts/call` — it does not apply to the Node.js REST API or the `/api/v1/blocks` route. [5](#0-4) 

**Root cause — tiny default connection pool:**

`rest/dbpool.js` initialises the pool with `max: config.db.pool.maxConnections`, whose documented default is **10**: [6](#0-5) [7](#0-6) 

Each query can hold a connection for up to the `statementTimeout` of 20 000 ms.

**Why existing checks fail:**

- The `responseCacheCheckHandler` in `rest/middleware/responseCacheHandler.js` would serve identical requests from Redis, but it is never registered unless the operator explicitly enables it — the default deployment is unprotected. [8](#0-7) 
- The `blockRoute.js` router attaches no per-route middleware beyond the controller itself. [9](#0-8) 

### Impact Explanation
With the pool at 10 connections and no rate limiting, an attacker holding all 10 connections with slow or concurrent queries blocks **every** REST API endpoint that shares the same `global.pool` — accounts, transactions, tokens, etc. New requests queue until `connectionTimeoutMillis` (20 000 ms) expires and then fail with a connection-timeout error, producing a complete REST API outage for legitimate users. This is a non-network DoS requiring no authentication.

### Likelihood Explanation
The attack requires only an HTTP client capable of sending concurrent GET requests — no credentials, no special knowledge, no exploit chain. The endpoint is publicly documented in the OpenAPI spec. A single attacker with a modest script (e.g., `ab -c 50 -n 10000 /api/v1/blocks?limit=100`) can sustain pool exhaustion indefinitely. The default-off cache means most deployments that have not explicitly configured Redis response caching are vulnerable out of the box.

### Recommendation
1. **Enable the response cache by default** or document it as a required production setting; the infrastructure already exists in `responseCacheHandler.js`.
2. **Add per-IP rate limiting** to the REST API using `express-rate-limit` (or equivalent), applied globally in `server.js` before route registration.
3. **Increase `maxConnections`** or front the pool with PgBouncer in transaction mode (already present in the Helm chart but not enforced for the REST service by default).
4. **Add a request concurrency limit** (e.g., `express-slow-down` or an in-flight counter) specifically for the `/api/v1/blocks` route.

### Proof of Concept
```bash
# Precondition: default deployment with cache.response.enabled=false (the default)
# No credentials required

# Step 1 – flood the endpoint with 50 concurrent connections
ab -c 50 -n 100000 'http://<mirror-node-host>:5551/api/v1/blocks?limit=100'

# Step 2 – in a separate terminal, observe legitimate requests timing out
curl -v 'http://<mirror-node-host>:5551/api/v1/transactions'
# Expected: connection hangs for ~20 s then returns a 500/503 or connection-timeout error

# Step 3 – stop the flood; service recovers once pool connections are released
```

The pool of 10 connections is saturated by step 1. Step 2 demonstrates that unrelated endpoints sharing `global.pool` are also denied service, confirming the cross-endpoint DoS impact.

### Citations

**File:** rest/controllers/blockController.js (L101-112)
```javascript
  getBlocks = async (req, res) => {
    const filters = utils.buildAndValidateFilters(req.query, acceptedBlockParameters);
    const formattedFilters = this.extractSqlFromBlockFilters(filters);
    const blocks = await RecordFileService.getBlocks(formattedFilters);

    res.locals[responseDataLabel] = {
      blocks: blocks.map((model) => new BlockViewModel(model)),
      links: {
        next: this.generateNextLink(req, blocks, formattedFilters),
      },
    };
  };
```

**File:** rest/server.js (L54-54)
```javascript
const applicationCacheEnabled = config.cache.response.enabled && config.redis.enabled;
```

**File:** rest/server.js (L95-98)
```javascript
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** docs/configuration.md (L549-549)
```markdown
| `hiero.mirror.rest.cache.response.enabled`                               | false                   | Whether or not the Redis based REST API response cache is enabled. If so, Redis itself must be enabled and properly configured.                                                               |
```

**File:** docs/configuration.md (L556-557)
```markdown
| `hiero.mirror.rest.db.pool.maxConnections`                               | 10                      | The maximum number of clients the database pool can contain                                                                                                                                   |
| `hiero.mirror.rest.db.pool.statementTimeout`                             | 20000                   | The number of milliseconds to wait before timing out a query statement                                                                                                                        |
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-20)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.local.SynchronizationStrategy;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.hiero.mirror.web3.throttle.ThrottleProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";
```

**File:** rest/dbpool.js (L14-14)
```javascript
  max: config.db.pool.maxConnections,
```

**File:** rest/middleware/responseCacheHandler.js (L40-48)
```javascript
const responseCacheCheckHandler = async (req, res) => {
  const startTime = res.locals[requestStartTime] || Date.now();
  const responseCacheKey = cacheKeyGenerator(req);
  const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);

  if (!cachedTtlAndValue) {
    res.locals[responseCacheKeyLabel] = responseCacheKey;
    return;
  }
```

**File:** rest/routes/blockRoute.js (L12-12)
```javascript
router.getExt('/', BlockController.getBlocks);
```
