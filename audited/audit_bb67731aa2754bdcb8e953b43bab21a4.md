### Title
Unauthenticated Cache Flooding via Unbounded `setSingle()` Writes Causes Redis Eviction Storms and Degraded Block Data Availability

### Summary
The REST API's `responseCacheUpdateHandler` middleware unconditionally writes every successful API response into Redis via `getCache().setSingle()` using a URL-derived cache key, with no per-IP or per-user rate limiting on cache writes. An unauthenticated attacker can flood the API with unique block-related URLs, filling Redis memory and triggering continuous LFU eviction storms that displace legitimate cached responses, forcing repeated database queries and degrading block data availability.

### Finding Description
**Code path:**

- `rest/middleware/responseCacheHandler.js`, `responseCacheUpdateHandler`, line 116:
  ```js
  await getCache().setSingle(responseCacheKey, ttl, cachedResponse);
  ```
- `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator`, line 151–153:
  ```js
  const cacheKeyGenerator = (req) => {
    return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
  };
  ```
- `rest/cache.js`, `setSingle`, lines 85–93:
  ```js
  async setSingle(key, expiry, value) {
    if (!this.ready) { return undefined; }
    return this.redis.setex(key, expiry, JSONStringify(value))
      .catch((err) => logger.warn(`Redis error during set: ${err.message}`));
  }
  ```

**Root cause:** Every unique `req.originalUrl` produces a unique MD5-based Redis key. `setSingle` calls `redis.setex` with no guard on write volume, no per-IP quota, and no deduplication beyond the URL itself. The REST middleware stack (`rest/server.js` lines 94–141) contains no rate-limiting layer — confirmed by the absence of any rate-limit middleware in `rest/**`. The `authHandler.js` only adjusts response result limits for authenticated users; it does not throttle request rates. Redis is bounded at 250 MB with `allkeys-lfu` eviction policy (configured in `rest/cache.js` lines 47–50 via `#setConfig`), which evicts least-frequently-used keys when full — but provides no protection against cache churn from a flood of single-use keys.

**Exploit flow:**
1. Attacker sends a high volume of GET requests to block-related endpoints with unique query parameters (e.g., `/api/v1/blocks?limit=1&block.number=gt:N` for N = 1, 2, 3, …).
2. Each unique URL misses the cache check in `responseCacheCheckHandler` (line 43–48), so the request proceeds to the database.
3. After the DB response, `responseCacheUpdateHandler` calls `setSingle` for each unique URL, writing a new Redis key.
4. Redis fills to 250 MB; `allkeys-lfu` begins evicting keys. Since attacker keys are each accessed only once, they have the lowest LFU score — but so do infrequently accessed legitimate block/transaction responses.
5. Legitimate cached responses are continuously evicted, causing cache miss storms and repeated DB queries for all users.

### Impact Explanation
The mirror node's Redis cache is the primary performance layer protecting the PostgreSQL database from repeated identical queries. Sustained cache flooding degrades block data availability through the REST API: every cache miss forces a full DB query, increasing latency and DB connection pool exhaustion (pool capped at 10 connections per `docs/configuration.md` line 556). Under sustained attack, the effective cache hit rate approaches zero, making the mirror node's block API functionally equivalent to an uncached service. This is a denial-of-service against the caching layer, not the Hedera network itself (the mirror node is read-only and does not participate in block production).

### Likelihood Explanation
Preconditions are minimal: no authentication, no API key, no privileged access required. The block number space is effectively unbounded (millions of valid block numbers exist on mainnet), providing an inexhaustible supply of unique cache-busting URLs. A single attacker with a modest script sending ~1,000 requests/second can fill 250 MB of Redis in seconds (each cached JSON response is typically 1–10 KB). The attack is trivially repeatable and requires no special tooling beyond `curl` or any HTTP client.

### Recommendation
1. **Add per-IP request rate limiting** to the REST Express app (e.g., `express-rate-limit`) before the `responseCacheCheckHandler` middleware in `rest/server.js`.
2. **Limit cache write rate**: Track and cap the number of new Redis keys written per time window, or skip caching for requests from IPs exceeding a threshold.
3. **Normalize cache keys**: Implement the planned request normalizer (referenced in `responseCacheHandler.js` line 149, issue #9113) to collapse semantically equivalent URLs (e.g., different orderings of the same query params) into a single cache key, reducing the unique key space.
4. **Increase Redis `maxMemory`** and tune `allkeys-lfu` decay factor to better protect frequently accessed keys from single-use flood keys.

### Proof of Concept
```bash
# Fill Redis with unique block cache entries (no auth required)
for i in $(seq 1 50000); do
  curl -s "https://<mirror-node-host>/api/v1/blocks?limit=1&block.number=gt:$i" &
done
wait

# Verify legitimate cached block is now a cache miss (forces DB query each time)
time curl "https://<mirror-node-host>/api/v1/blocks?limit=1"
# Observe elevated latency vs. pre-flood baseline due to cache eviction
```

Each iteration writes a new `setex` key in Redis via `setSingle`. After Redis reaches 250 MB, LFU eviction continuously displaces cached responses, causing all subsequent requests — including for popular block queries — to hit the database.