### Title
Cache Stampede via Unguarded Check-Then-Act in `responseCacheCheckHandler`

### Summary
`responseCacheCheckHandler` performs a cache lookup and, on miss, allows the request to fall through to the backend with no in-flight deduplication, distributed lock, or atomic SET-if-not-exists guard. Any unprivileged external user can send N concurrent requests to the same cold or just-expired URL, causing all N requests to simultaneously miss the cache, hit the database backend, and redundantly write to Redis — a textbook cache stampede / thundering herd.

### Finding Description

**Singleton pattern (not the root cause, but the shared surface):** [1](#0-0) 

The singleton ensures one `Cache` instance, but provides no coordination between concurrent callers.

**Cache check — no lock, no in-flight tracking:** [2](#0-1) 

On a cache miss, the handler sets `res.locals[responseCacheKeyLabel]` and returns. There is no mechanism to signal to other concurrent requests that a backend fetch is already in progress for this key.

**Cache write — `SETEX` always overwrites, no NX guard:** [3](#0-2) 

`setSingle` uses Redis `SETEX`, which unconditionally overwrites. There is no `SET key value EX ttl NX` (set-if-not-exists) to let only the first writer win and discard the rest.

**Exploit flow:**

1. Cache for `/api/v1/accounts?limit=100` is cold (empty or just expired).
2. Attacker sends 500 concurrent GET requests to that URL.
3. All 500 requests reach `getSingleWithTtl` before any write completes — all get `undefined` (cache miss).
4. All 500 set `res.locals[responseCacheKeyLabel]` and fall through to the database route handler.
5. All 500 execute the full database query.
6. All 500 call `responseCacheUpdateHandler` → `setSingle` → `SETEX` — 500 redundant Redis writes of identical data.

The `await` at line 43 yields the event loop, so Node.js's single-threaded model does **not** prevent this interleaving; all 500 `getSingleWithTtl` calls are dispatched before any response returns.

### Impact Explanation

- **Backend amplification**: A single logical request becomes N database queries. For expensive queries (large result sets, complex joins), this directly amplifies DB CPU and I/O load proportional to attacker concurrency.
- **Redis write storm**: N redundant `SETEX` calls for the same key, wasting Redis bandwidth and CPU.
- **Availability**: Sustained stampede attacks against multiple endpoints can exhaust DB connection pools, causing cascading 503 errors for all users.
- **No data corruption**: Writes are idempotent (same value), so correctness is not affected — only availability and performance.

Severity: **Medium–High** (unauthenticated DoS amplification).

### Likelihood Explanation

- **Zero privilege required**: All affected endpoints are public read APIs (GET `/api/v1/accounts`, `/api/v1/tokens`, etc.).
- **Trivially reproducible**: A single `ab -n 500 -c 500 <url>` or equivalent suffices.
- **Repeatable**: The attacker can re-trigger on every cache TTL expiry (as low as `DEFAULT_REDIS_EXPIRY = 1` second).
- **No rate limiting visible** in the middleware chain between the internet and `responseCacheCheckHandler`. [4](#0-3) 

### Recommendation

1. **Probabilistic early expiration / stale-while-revalidate**: Serve the stale cached value while one background request refreshes it.
2. **Redis distributed lock (preferred)**: Before falling through to the backend on a miss, attempt `SET lock:<key> 1 EX <short_ttl> NX`. Only the winner fetches; losers either wait and retry or serve a stale value.
3. **In-process promise coalescing**: Keep a `Map<cacheKey, Promise>` of in-flight backend fetches. Concurrent misses for the same key attach to the existing promise instead of issuing a new backend request.
4. **`SET NX` on write**: Change `setSingle` to use `SET key value EX ttl NX` so only the first writer populates the key, reducing redundant writes even without a pre-fetch lock.

### Proof of Concept

```bash
# 1. Ensure cache is cold (restart or wait for TTL expiry)
# 2. Fire 200 concurrent requests to the same endpoint
ab -n 200 -c 200 "http://<mirror-node-host>/api/v1/accounts?limit=25"

# 3. Observe in DB slow-query log / pg_stat_activity:
#    200 identical SELECT queries executing simultaneously

# 4. Observe in Redis monitor:
redis-cli monitor | grep SETEX
# → 200 SETEX calls for the same key within milliseconds
```

The window of vulnerability equals the backend response latency. For slow queries (e.g., 500 ms), an attacker sustaining 200 req/s can keep the stampede perpetually active by timing new bursts to coincide with each TTL expiry.

### Citations

**File:** rest/middleware/responseCacheHandler.js (L29-37)
```javascript
const getCache = (() => {
  let cache;
  return () => {
    if (!cache) {
      cache = new Cache();
    }
    return cache;
  };
})();
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

**File:** rest/server.js (L94-98)
```javascript
// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```
