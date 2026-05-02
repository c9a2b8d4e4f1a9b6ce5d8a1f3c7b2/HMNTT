### Title
Cache Key Pollution via Unpermuted `timestamp` Parameter Ordering — N! Cache Entry Amplification

### Summary
The `cacheKeyGenerator` in `responseCacheHandler.js` hashes `req.originalUrl` directly without normalization, while `normalizeRequestQueryParams()` in `requestNormalizer.js` is explicitly disconnected from the cache pipeline (acknowledged in a TODO comment). Because `timestamp` is intentionally excluded from sorting in `NON_SORTED_PARAMS`, every distinct ordering of N `timestamp` query parameters produces a unique MD5 cache key, allowing an unauthenticated attacker to create N! Redis entries for identical underlying data, exhausting cache memory and evicting legitimate entries.

### Finding Description

**Exact code path:**

`rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator`, line 151–152:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
The key is derived from the raw, unnormalized `req.originalUrl`. The comment at line 149 explicitly admits the normalizer is not yet wired in:
> *"In the future, this will utilize Edwin's request normalizer (9113)."*

`rest/middleware/requestNormalizer.js`, `NON_SORTED_PARAMS`, line 23:
```js
const NON_SORTED_PARAMS = COLLAPSABLE_PARAMS.concat([filterKeys.BLOCK_NUMBER, filterKeys.TIMESTAMP]);
```
`timestamp` is deliberately excluded from sorting in `getNormalizedArrayValue` (line 70–71):
```js
if (!NON_SORTED_PARAMS.includes(name)) {
  valueArray.sort();
}
```

**Root cause:** `normalizeRequestQueryParams()` is never called in the middleware pipeline before `responseCacheCheckHandler` runs. A grep across the entire codebase confirms `normalizeRequestQueryParams` is only referenced in its own source file and its unit test — it is dead code with respect to the cache subsystem. Even if it were wired in, `timestamp` is explicitly excluded from sorting, so permutation-based key divergence would persist.

**Exploit flow:**
1. Attacker identifies any endpoint accepting multiple `timestamp` parameters (e.g., `/api/v1/transactions?timestamp=gte:1000&timestamp=lt:2000`).
2. Attacker sends all N! orderings of N `timestamp` values. Each request produces a distinct `req.originalUrl`, a distinct MD5 hash, and therefore a distinct Redis key.
3. Each cache miss triggers a full DB query and stores a new Redis entry.
4. Redis fills to `maxmemory`; the configured `maxmemory-policy` begins evicting legitimate cached entries.

### Impact Explanation
With N=8 timestamp values, an attacker generates 40,320 distinct Redis entries for a single logical query. With N=10, that is 3,628,800 entries. Redis memory is exhausted, legitimate cached responses are evicted, and every subsequent legitimate request becomes a cache miss that hits the database — degrading API performance for all users. No authentication or special privilege is required; the REST API is publicly accessible.

### Likelihood Explanation
Any unauthenticated user can craft HTTP GET requests with reordered query parameters. No exploit tooling is needed beyond a simple script iterating permutations. The attack is repeatable, stateless, and requires no knowledge of internal state. The TTL on cached entries (derived from `cache-control: max-age`) means the attacker must only sustain the flood long enough to keep the cache polluted.

### Recommendation
1. **Immediate:** Wire `normalizeRequestQueryParams()` into `cacheKeyGenerator` so the normalized URL — not `req.originalUrl` — is hashed as the cache key. This is the stated intent of the existing TODO at line 149.
2. **For `timestamp` specifically:** Since `timestamp` ordering is semantically significant (per the spec-test comment in `requestNormalizer.js` lines 17–22), the normalized key for `timestamp` should canonicalize the set of values (e.g., sort them for cache-key purposes only, while preserving original order for the actual DB query). Alternatively, cap the number of accepted `timestamp` parameters per request via OpenAPI validation.
3. **Defense-in-depth:** Apply a per-IP rate limit on cache-miss-inducing requests and set a hard Redis `maxmemory` with an appropriate eviction policy (`allkeys-lru`) to bound blast radius.

### Proof of Concept
```bash
# Endpoint accepting multiple timestamp params
BASE="http://localhost:5551/api/v1/transactions"

# Generate all 6 permutations of 3 timestamp values
TIMESTAMPS=("gte:1000000000" "lt:2000000000" "1500000000")

for p in \
  "timestamp=${TIMESTAMPS[0]}&timestamp=${TIMESTAMPS[1]}&timestamp=${TIMESTAMPS[2]}" \
  "timestamp=${TIMESTAMPS[0]}&timestamp=${TIMESTAMPS[2]}&timestamp=${TIMESTAMPS[1]}" \
  "timestamp=${TIMESTAMPS[1]}&timestamp=${TIMESTAMPS[0]}&timestamp=${TIMESTAMPS[2]}" \
  "timestamp=${TIMESTAMPS[1]}&timestamp=${TIMESTAMPS[2]}&timestamp=${TIMESTAMPS[0]}" \
  "timestamp=${TIMESTAMPS[2]}&timestamp=${TIMESTAMPS[0]}&timestamp=${TIMESTAMPS[1]}" \
  "timestamp=${TIMESTAMPS[2]}&timestamp=${TIMESTAMPS[1]}&timestamp=${TIMESTAMPS[0]}"
do
  curl -s -o /dev/null -w "%{http_code} $p\n" "$BASE?$p"
done
# Each request gets a cache MISS and stores a new Redis entry.
# Scale N to exhaust Redis memory.
```