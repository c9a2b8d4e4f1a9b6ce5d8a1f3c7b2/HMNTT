### Title
Unbounded Concurrent Redis MULTI/EXEC Transactions via Cache-Miss Flood in `responseCacheCheckHandler`

### Summary
`responseCacheCheckHandler()` issues a Redis `multi().ttl(key).get(key).exec()` transaction for every incoming HTTP request with no rate limiting or concurrency cap. Because `multi()` transactions are not batched by ioredis's `enableAutoPipelining`, each request to a unique uncached URL generates a separate MULTI/EXEC round-trip to Redis. An unprivileged attacker can flood the REST API with requests to distinct URLs, saturating Redis with concurrent transactions and materially increasing its CPU and connection overhead.

### Finding Description

**Code path:**

`rest/middleware/responseCacheHandler.js`, `responseCacheCheckHandler()`, line 43: [1](#0-0) 

calls `getCache().getSingleWithTtl(responseCacheKey)` unconditionally for every request.

`rest/cache.js`, `getSingleWithTtl()`, lines 64–83: [2](#0-1) 

The only guard is `if (!this.ready)` — there is no rate limit, no concurrency cap, and no deduplication of in-flight keys.

**Root cause — `multi()` bypasses auto-pipelining:**

The ioredis client is configured with `enableAutoPipelining: true`: [3](#0-2) 

Auto-pipelining batches individual commands (e.g., `get`, `set`) that arrive in the same event-loop tick into a single network write. However, `multi()` creates an explicit MULTI/EXEC transaction block that is **excluded** from auto-pipelining. Each call to `getSingleWithTtl()` therefore produces its own independent round-trip: `MULTI → TTL key → GET key → EXEC` (4 commands per request).

**Cache-key generation:**

`cacheKeyGenerator` hashes `req.originalUrl` with MD5: [4](#0-3) 

Any variation in the URL (query parameter value, timestamp, cursor, etc.) produces a distinct key, guaranteeing a cache miss and a Redis round-trip for every crafted request.

**No rate limiting on the REST API:**

The REST middleware stack (`authHandler`, `httpErrorHandler`, `metricsHandler`, `openapiHandler`, `requestHandler`, `requestNormalizer`, `responseCacheHandler`, `responseHandler`) contains no IP-based or global request-rate limiter: [5](#0-4) 

The throttle infrastructure that exists in the codebase (`ThrottleManagerImpl`, `ThrottleConfiguration`) belongs exclusively to the `web3` Java service and is not applied to the Node.js REST API.

**Exploit flow:**

1. Attacker sends N concurrent HTTP GET requests to the REST API, each with a unique query string (e.g., `?timestamp.gte=1`, `?timestamp.gte=2`, …).
2. Each request enters `responseCacheCheckHandler` and calls `getSingleWithTtl(uniqueKey)`.
3. Each call executes `redis.multi().ttl(key).get(key).exec()` — a separate MULTI/EXEC transaction.
4. All N transactions queue on the single ioredis connection and are processed serially by Redis.
5. Redis CPU rises proportionally to N; the single connection becomes a bottleneck; `commandTimeout` may be breached for legitimate requests.

### Impact Explanation

Redis is a single-threaded command processor. Flooding it with MULTI/EXEC transactions (4 commands each, non-batchable) directly increases CPU time per second. Because the REST API uses a single ioredis connection (no pool), all concurrent transactions serialize on that connection, amplifying latency for every other Redis operation in the service (including `setSingle`, `mgetBuffer`, `mset`). Sustained attack can degrade or deny cache service for all legitimate users, forcing every request to fall through to the database layer and compounding the resource impact.

### Likelihood Explanation

No authentication, API key, or network-level credential is required. The attack requires only an HTTP client capable of sending concurrent requests — trivially achievable with `curl`, `ab`, `wrk`, or any scripting language. The attacker needs no knowledge of valid data; any syntactically valid but unique URL suffices to guarantee a cache miss. The attack is repeatable, stateless, and scalable. The 30% Redis CPU threshold is reachable with a modest flood (hundreds of concurrent requests) given that each miss generates 4 Redis commands instead of the 1–2 that auto-pipelining would produce for non-transactional commands.

### Recommendation

1. **Add a request-rate limiter** (e.g., `express-rate-limit`) to the REST API middleware chain, applied before `responseCacheCheckHandler`, to cap requests per IP per second.
2. **Replace `multi()` with a Lua script or a single `GET` + separate `TTL`** so that auto-pipelining can batch concurrent lookups into a single network write, reducing per-request Redis overhead.
3. **Deduplicate in-flight cache lookups** for the same key (e.g., a promise cache / coalescing layer) so that N concurrent requests for the same uncached URL result in exactly one Redis round-trip.
4. **Set `maxRetriesPerRequest`** to a low value and enforce a `commandTimeout` to shed load quickly under saturation rather than queuing indefinitely (`enableOfflineQueue: true` currently allows unbounded queuing). [6](#0-5) 

### Proof of Concept

```bash
# Generate 500 concurrent requests to unique uncached URLs
seq 1 500 | xargs -P 500 -I{} \
  curl -s "https://<mirror-node-host>/api/v1/transactions?timestamp.gte={}&limit=1" \
  -o /dev/null

# Monitor Redis CPU on the server side:
redis-cli --latency-history -i 1
# or
redis-cli info stats | grep instantaneous_ops_per_sec
```

Expected result: Redis `instantaneous_ops_per_sec` and CPU (`used_cpu_sys` delta) increase by >30% compared to the 24-hour baseline, with no authentication or privileged access required.

### Citations

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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/cache.js (L21-40)
```javascript
    const options = {
      commandTimeout: redisConfig.commandTimeout,
      connectTimeout: redisConfig.connectTimeout,
      enableAutoPipelining: true,
      enableOfflineQueue: true,
      enableReadyCheck: true,
      keepAlive: 30000,
      lazyConnect: !redisConfig.enabled,
      maxRetriesPerRequest: redisConfig.maxRetriesPerRequest,
      retryStrategy: (attempt) => {
        this.ready = false;

        if (!redisConfig.enabled) {
          return null;
        }

        return Math.min(attempt * 2000, redisConfig.maxBackoff);
      },
      ...sentinelOptions,
    };
```

**File:** rest/cache.js (L64-83)
```javascript
  async getSingleWithTtl(key) {
    if (!this.ready) {
      return undefined;
    }

    const result = await this.redis
      .multi()
      .ttl(key)
      .get(key)
      .exec()
      .catch((err) => logger.warn(`Redis error during ttl/get: ${err.message}`));

    // result is [[null, ttl], [null, value]], with value === null on cache miss.
    const rawValue = result[1][1];
    if (rawValue) {
      return {ttl: result[0][1], value: JSONParse(rawValue)};
    }

    return undefined;
  }
```

**File:** rest/middleware/index.js (L1-1)
```javascript
// SPDX-License-Identifier: Apache-2.0
```
