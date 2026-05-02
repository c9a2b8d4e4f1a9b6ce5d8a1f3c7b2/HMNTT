### Title
URL Encoding Cache Key Collision — Cache Bypass and Stale Data Inconsistency via `cacheKeyGenerator()`

### Summary
`cacheKeyGenerator()` in `rest/middleware/responseCacheHandler.js` hashes `req.originalUrl` directly with MD5, without any URL normalization or percent-decoding. Because `req.originalUrl` is the raw string as received by Express, logically identical requests with different percent-encodings (e.g., `limit=1` vs `limit=%31`, `account.id=0.0.18` vs `account.id=0.0.%31%38`) produce distinct MD5 hashes and therefore distinct Redis cache keys. Any unprivileged external user can exploit this to permanently bypass the cache, pollute Redis with duplicate entries, and cause different users to observe data of different ages for the same logical resource.

### Finding Description
**Exact code path:**
`rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, line 151–153:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
`req.originalUrl` is Express's raw, un-normalized URL string. No `decodeURIComponent`, no query-parameter sorting, no `+`→space normalization is applied before hashing.

The comment at line 149 explicitly acknowledges the missing normalization:
> `path?query - In the future, this will utilize Edwin's request normalizer (9113).`

**Root cause:** The function assumes `req.originalUrl` is already in a canonical form. This assumption is false: HTTP allows any unreserved character to be percent-encoded, and `+` vs `%20` for spaces in query strings are both legal and semantically equivalent. Express's query parser (`req.query`) normalizes these when routing, but `req.originalUrl` is never touched.

**Exploit flow:**
1. Attacker sends `GET /api/v1/accounts?account.id=0.0.18&limit=1` → cache miss → DB hit → result stored under key `K1 = MD5("/api/v1/accounts?account.id=0.0.18&limit=1")`.
2. Attacker (or any user) sends `GET /api/v1/accounts?account.id=0.0.%31%38&limit=%31` → cache miss (key `K2 ≠ K1`) → second DB hit → result stored under key `K2`.
3. Both `K1` and `K2` now exist in Redis with independent TTLs, representing the same logical resource.
4. If the underlying data changes between the two requests, `K1` holds stale data and `K2` holds fresh data. Users hitting `K1` receive stale mirror node records; users hitting `K2` receive current records — for the same logical query.
5. An attacker can repeat step 2 with a new encoding variant on every request, ensuring every request is a cache miss and hits the database directly.

**Why existing checks are insufficient:** There are none. No normalization layer exists before `cacheKeyGenerator()` is called. `responseCacheCheckHandler` calls `cacheKeyGenerator(req)` directly at line 42 with the raw request object.

### Impact Explanation
- **Stale/inconsistent records served to users:** Two users querying the same mirror node resource (same account, same filters) can receive data of different ages because their requests map to different cache keys with different creation timestamps and TTLs.
- **Cache bypass / DB amplification:** An attacker can trivially force every request to bypass the cache by percent-encoding one character in the URL, causing all requests to hit the database. This degrades mirror node availability under load.
- **Redis cache pollution:** Each encoding variant creates a separate Redis entry, wasting memory proportional to the number of variants an attacker generates.

Severity: **Medium**. Data served is not fabricated, but it can be stale relative to what other users see for the same resource, which violates the correctness guarantee of the mirror node API.

### Likelihood Explanation
No authentication or special privilege is required. Any HTTP client can percent-encode query parameter characters. The encoding variants are trivially generated (e.g., encode any digit or letter in a parameter value). The attack is fully repeatable and automatable. The code comment at line 149 confirms the developers are aware of the missing normalization, meaning it has been present since the cache was introduced.

### Recommendation
Normalize `req.originalUrl` before hashing in `cacheKeyGenerator()`:
1. Percent-decode the full URL with `decodeURIComponent`.
2. Re-encode canonically (or use a URL parser to extract and sort query parameters).
3. Alternatively, build the cache key from `req.path` + sorted, decoded `req.query` entries rather than from `req.originalUrl`.

Example minimal fix:
```js
const cacheKeyGenerator = (req) => {
  const url = new URL(req.originalUrl, 'http://x');
  url.searchParams.sort(); // canonical parameter order
  const normalized = url.pathname + '?' + url.searchParams.toString();
  return crypto.createHash('md5').update(normalized).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
This is consistent with the referenced issue 9113 ("Edwin's request normalizer").

### Proof of Concept
```bash
# Step 1: Warm the cache with the canonical URL
curl -s "https://<mirror-node>/api/v1/accounts?account.id=0.0.18&limit=1"
# → 200, result cached under K1

# Step 2: Request the same resource with percent-encoded parameters
curl -s "https://<mirror-node>/api/v1/accounts?account.id=0.0.%31%38&limit=%31"
# → 200, cache MISS (K2 ≠ K1), fresh DB hit, cached under K2

# Step 3: Verify two independent cache entries exist (different TTLs)
# If data changed between steps 1 and 2, the two responses will differ
# despite being logically identical queries.

# Step 4: Repeat step 2 with a new encoding on every request to permanently
# bypass the cache and force every request to hit the database:
for i in $(seq 1 100); do
  curl -s "https://<mirror-node>/api/v1/accounts?account.id=0.0.%31%38&limit=%3$i"
done
# Each request is a cache miss; DB is hit 100 times instead of 1.
```