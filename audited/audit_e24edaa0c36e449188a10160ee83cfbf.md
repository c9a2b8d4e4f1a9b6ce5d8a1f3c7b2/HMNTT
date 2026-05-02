### Title
Unbounded Response Body Stored in Redis Cache Enables Cache Pollution via Unprivileged Requests

### Summary
`responseCacheUpdateHandler()` in `rest/middleware/responseCacheHandler.js` stores the full `res.locals[responseBodyLabel]` into Redis via `getCache().setSingle()` with no per-value size check. An unprivileged attacker can issue many distinct GET requests (varying query parameters to generate unique cache keys) that each return large responses, flooding Redis with large entries and causing LFU-based eviction of legitimate cached responses, degrading cache effectiveness and increasing database load.

### Finding Description
**Exact code path:**

In `rest/middleware/responseCacheHandler.js`, `responseCacheUpdateHandler()` (lines 90–119):
```js
const responseBody = res.locals[responseBodyLabel];
// ...
const cachedResponse = new CachedApiResponse(statusCode, headers, responseBody, shouldCompress(responseBody));
await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
```
The only guards are: `responseBody` is truthy, `responseCacheKey` exists, status is success/304, and `ttl > 0`. There is **no check on the byte size of `responseBody`** before calling `setSingle()`.

In `rest/cache.js`, `setSingle()` (lines 85–93):
```js
async setSingle(key, expiry, value) {
  return this.redis.setex(key, expiry, JSONStringify(value))
    .catch((err) => logger.warn(...));
}
```
No size guard here either.

**Cache key generation** (`cacheKeyGenerator`, line 151–153) uses MD5 of `req.originalUrl`, so every distinct URL (different query parameters) produces a unique Redis key. An attacker can trivially generate thousands of unique keys.

**Root cause:** The code assumes all API responses are small enough to cache safely. The REST API's `response.limit.max` (default 100) bounds the number of items per page, but a 100-transaction response with many transfers, token transfers, NFT transfers, and staking reward transfers can be hundreds of KB uncompressed. Even with gzip compression (`compressThreshold: 150`), many distinct large entries can collectively exhaust the 250 MB Redis `maxmemory` limit.

**Why existing checks fail:**
- `shouldCompress()` reduces individual entry size but does not prevent storage.
- `allkeys-lfu` eviction handles memory pressure gracefully (no crash), but evicts the least-frequently-used keys — which may be legitimate cached responses that have not yet accumulated high access counts.
- There is **no application-level rate limiting** on the REST API (the throttle found in the codebase applies only to the web3/EVM API).

### Impact Explanation
When the response cache is enabled (`cache.response.enabled: true`), an attacker can:
1. Flood Redis with many large, unique-keyed cache entries.
2. Trigger `allkeys-lfu` eviction of legitimate cached responses (those with lower access frequency).
3. Force cache misses for legitimate users, increasing database query load.
4. Sustain this pressure to keep the cache in a degraded state.

Redis will not crash (eviction prevents OOM), but cache effectiveness is continuously undermined. Under sustained attack, the database connection pool (`db.pool.maxConnections: 10`) becomes a bottleneck as cache misses multiply, potentially causing query timeouts (`db.pool.statementTimeout: 20000 ms`) and degraded API response times.

### Likelihood Explanation
- **Precondition:** `cache.response.enabled` must be `true` (non-default, but documented and intended for production use).
- **No authentication required:** The REST API is public; no credentials are needed to issue GET requests.
- **No rate limiting:** The REST API has no application-level rate limiter. An attacker with a modest HTTP client can issue hundreds of requests per second.
- **Unique keys are trivial to generate:** Varying `timestamp`, `account.id`, or `limit` parameters produces distinct MD5 cache keys.
- **Repeatability:** The attack is fully repeatable and can be automated with a simple script.

### Recommendation
1. **Add a per-value size limit** in `responseCacheUpdateHandler()` before calling `setSingle()`:
   ```js
   const MAX_CACHEABLE_BODY_BYTES = 512 * 1024; // e.g., 512 KB
   if (responseBody.length > MAX_CACHEABLE_BODY_BYTES) return;
   ```
2. **Add application-level rate limiting** to the REST API middleware (e.g., using `express-rate-limit` per IP).
3. **Consider a Redis `proto-max-bulk-len` or client-side size guard** to reject oversized values at the Redis client layer.
4. **Monitor Redis eviction rate** (`redis_evicted_keys`) and alert on anomalies.

### Proof of Concept
```bash
# Assumes cache.response.enabled=true and the mirror node is running locally

# Generate 5000 unique requests with varying timestamp ranges to flood the cache
for i in $(seq 1 5000); do
  curl -s "http://localhost:5551/api/v1/transactions?limit=100&timestamp=gte:${i}000000000&timestamp=lte:$((i+1))000000000" &
done
wait

# Observe Redis memory usage and eviction count
redis-cli info memory | grep used_memory_human
redis-cli info stats | grep evicted_keys

# Legitimate cached entries (e.g., frequently accessed accounts) will show
# increased cache miss rates as their keys are evicted to make room.
```