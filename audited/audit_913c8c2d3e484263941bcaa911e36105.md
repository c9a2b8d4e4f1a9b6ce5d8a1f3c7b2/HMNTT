### Title
Unbounded Pending Promise Accumulation in `responseCacheUpdateHandler` During Partial Redis Network Partition

### Summary
When Redis is slow but not fully unreachable (partial network partition), `responseCacheUpdateHandler` awaits a `setex` call that does not resolve until `commandTimeout` (default 10 seconds). Because `extendExpress.js` wraps every middleware with `await promise`, each concurrent HTTP request holds its full in-memory state (req, res, serialized response body) for the entire duration of the stalled Redis command. An unprivileged attacker flooding the public API with concurrent GET requests during such a partition can accumulate thousands of suspended async frames, exhausting Node.js heap memory.

### Finding Description

**Code path:**

`rest/server.js` line 140 registers `responseCacheUpdateHandler` via `app.useExt(responseCacheUpdateHandler)`.

`rest/extendExpress.js` lines 31–45 — the `wrap` function unconditionally `await`s the promise returned by every middleware:
```js
const promise = fn.apply(null, arguments);
if (promise && typeof promise.then === 'function') {
  await promise;   // ← suspends here until Redis responds
  ...
}
```

`rest/middleware/responseCacheHandler.js` lines 90–119 — `responseCacheUpdateHandler` calls:
```js
await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
```

`rest/cache.js` lines 85–93 — `setSingle` only guards with `this.ready`:
```js
async setSingle(key, expiry, value) {
  if (!this.ready) { return undefined; }
  return this.redis
    .setex(key, expiry, JSONStringify(value))
    .catch((err) => logger.warn(...));
}
```

**Root cause:** During a partial partition, the TCP connection to Redis remains established so `this.ready` stays `true` (it is only set to `false` inside `retryStrategy`, which fires only on connection loss). The `setex` call is issued and enters ioredis's in-flight queue, but Redis never acknowledges it until `commandTimeout` (default **10 000 ms**) elapses. Because `wrap` awaits the entire middleware promise, the Express request pipeline is suspended for up to 10 s per request. There is no cap on how many requests can be simultaneously suspended.

**Failed assumption:** The design assumes Redis either responds quickly or is fully down (triggering `this.ready = false`). A slow-but-connected Redis invalidates both branches.

### Impact Explanation
Each suspended request retains: the `req`/`res` Express objects, the full serialized JSON response body (up to the configured response limit), the `CachedApiResponse` wrapper, and the entire async call stack. With `commandTimeout = 10 000 ms` and `maxRetriesPerRequest = 1`, each promise can be pending for ~20 s. An attacker sending 500 req/s sustains ~10 000 concurrent suspended frames. For endpoints returning large payloads (e.g., `/api/v1/transactions`, `/api/v1/tokens`), each frame can hold tens of kilobytes, leading to gigabytes of heap pressure and eventual OOM crash — a complete denial of service of the REST API process.

### Likelihood Explanation
The attack requires no credentials; all affected routes are public GET endpoints. Partial Redis partitions are realistic in cloud environments (network congestion, Redis CPU saturation, sentinel failover in progress). The attacker needs only a moderate request rate (achievable with a single machine) and knowledge that the service uses Redis caching (inferable from response headers such as `cache-control: public, max-age=…`). The condition is repeatable and can be sustained as long as the partition persists.

### Recommendation
1. **Add a concurrency/queue limit for pending Redis write operations.** Reject or fire-and-forget the `setSingle` call when a configurable number of Redis writes are already in-flight.
2. **Do not `await` the cache-update write in the hot path.** Change `responseCacheUpdateHandler` to fire-and-forget the `setSingle` promise (with its own `.catch`) so the Express pipeline is not held open waiting for Redis:
   ```js
   getCache().setSingle(responseCacheKey, ttl, cachedResponse)
     .catch((err) => logger.warn(`Cache update failed: ${err.message}`));
   // do NOT await
   ```
3. **Reduce `commandTimeout`** to a value appropriate for a cache (e.g., 500–1000 ms) so that even if awaited, the window is short.
4. **Set `enableOfflineQueue: false`** to prevent unbounded command queuing when the connection is degraded.

### Proof of Concept
**Preconditions:**
- Mirror Node REST API running with `cache.response.enabled = true` and `redis.enabled = true`.
- Redis reachable at the TCP level but artificially slowed (e.g., via `tc qdisc add dev eth0 root netem delay 15000ms` on the Redis host, or a transparent proxy introducing latency > `commandTimeout`).

**Steps:**
1. Induce a partial partition: introduce >10 s RTT to Redis while keeping the TCP connection alive (so `this.ready` remains `true`).
2. From an unprivileged client, send a flood of concurrent GET requests:
   ```bash
   ab -n 50000 -c 500 http://<mirror-node>/api/v1/transactions
   ```
3. Observe Node.js heap growth via `process.memoryUsage()` or a metrics endpoint. Each request that passes `responseCacheCheckHandler` (which also stalls, but eventually returns a cache miss) will reach `responseCacheUpdateHandler` and suspend for ~10 s.
4. With 500 concurrent requests each holding ~50 KB of response data for 10 s, heap grows by ~25 MB per second of sustained attack. OOM is reached within minutes on a default-configured instance. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest/middleware/responseCacheHandler.js (L90-119)
```javascript
const responseCacheUpdateHandler = async (req, res) => {
  const responseCacheKey = res.locals[responseCacheKeyLabel];
  const responseBody = res.locals[responseBodyLabel];
  const isUnmodified = res.statusCode === httpStatusCodes.UNMODIFIED.code;

  if (responseBody && responseCacheKey && (isUnmodified || httpStatusCodes.isSuccess(res.statusCode))) {
    const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
    if (ttl > 0) {
      // There's no content-type header when code is 304, so get it from the default headers and override with the
      // optional headers from response.locals
      const headers = !isUnmodified
        ? res.getHeaders()
        : {
            ...config.response.headers.default,
            ...res.getHeaders(),
            ...(res.locals[responseHeadersLabel] ?? {}),
          };

      // Delete headers that will be re-computed when response later served by cache hit
      delete headers[CACHE_CONTROL_HEADER];
      delete headers[CONTENT_ENCODING_HEADER];
      delete headers[CONTENT_LENGTH_HEADER];
      delete headers[VARY_HEADER];

      const statusCode = isUnmodified ? httpStatusCodes.OK.code : res.statusCode;
      const cachedResponse = new CachedApiResponse(statusCode, headers, responseBody, shouldCompress(responseBody));
      await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
    }
  }
};
```

**File:** rest/cache.js (L21-51)
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
    const uriSanitized = uri.replaceAll(RegExp('(?<=//).*:.+@', 'g'), '***:***@');
    this.ready = false;

    this.redis = new Redis(uri, options)
      .on('connect', () => logger.info(`Connected to ${uriSanitized}`))
      .on('error', (err) => logger.error(`Error connecting to ${uriSanitized}: ${err.message}`))
      .on('ready', () => {
        this.#setConfig('maxmemory', redisConfig.maxMemory);
        this.#setConfig('maxmemory-policy', redisConfig.maxMemoryPolicy);
        this.ready = true;
      });
```

**File:** rest/cache.js (L85-93)
```javascript
  async setSingle(key, expiry, value) {
    if (!this.ready) {
      return undefined;
    }

    return this.redis
      .setex(key, expiry, JSONStringify(value))
      .catch((err) => logger.warn(`Redis error during set: ${err.message}`));
  }
```

**File:** rest/extendExpress.js (L31-45)
```javascript
const wrap = (fn) => {
  const isErrorHandler = fn.length === 4;
  const wrapped = async function () {
    // Ensure next function is only ran once
    arguments[2 + isErrorHandler] = _once(arguments[2 + isErrorHandler]);
    try {
      const promise = fn.apply(null, arguments);
      if (promise && typeof promise.then === 'function') {
        await promise;
        arguments[1 + isErrorHandler].headersSent ? null : arguments[2 + isErrorHandler]();
      }
    } catch (err) {
      arguments[1 + isErrorHandler].headersSent ? null : arguments[2 + isErrorHandler](err);
    }
  };
```
