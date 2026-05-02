### Title
Cache Key Bypass via URL Percent-Encoding in `cacheKeyGenerator()`

### Summary
`cacheKeyGenerator()` hashes `req.originalUrl` directly without any URL normalization or percent-decoding. Because Express preserves the raw, client-supplied URL in `req.originalUrl`, semantically identical requests with different percent-encodings (e.g., `limit=1%30` vs `limit=10`, or `0.0%2E1` vs `0.0.1`) produce distinct MD5 hashes and therefore distinct Redis keys, causing guaranteed cache misses. Any unprivileged user can exploit this to permanently bypass the response cache and force every request to hit the upstream database.

### Finding Description
**File:** `rest/middleware/responseCacheHandler.js`, lines 151–153

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` in Express is the verbatim URL string as received from the TCP stream — percent-encoding is never decoded before it is fed to `crypto.createHash('md5').update(...)`. The code comment at line 149 explicitly acknowledges the absence of normalization:

> `path?query - In the future, this will utilize Edwin's request normalizer (9113).`

Because MD5 is a byte-exact hash, any difference in the raw URL string — even a single `%2E` vs `.` or `%30` vs `0` — produces a completely different digest and therefore a different Redis key. The cache check at line 43 (`getCache().getSingleWithTtl(responseCacheKey)`) will always miss for the encoded variant, and the update at line 116 (`getCache().setSingle(responseCacheKey, ttl, cachedResponse)`) will store the result under the encoded key, which is never reused by canonical clients.

**Exploit flow:**
1. Legitimate clients populate the cache with canonical keys, e.g., MD5(`/api/v1/blocks?limit=10`).
2. Attacker sends `GET /api/v1/blocks?limit=1%30` — Express routes this identically (query parser decodes `%30` → `0`), but `req.originalUrl` is `/api/v1/blocks?limit=1%30`, producing a different MD5.
3. Cache miss → full upstream DB query → result stored under the encoded key.
4. Attacker rotates through the 256 possible single-byte encodings of any digit or letter in the query string, generating up to hundreds of distinct cache keys for the same logical request.
5. No existing check in `responseCacheCheckHandler` or `responseCacheUpdateHandler` normalizes or deduplicates keys.

### Impact Explanation
Every cache miss forces a full database query for block/account/transaction data. An attacker sending a continuous stream of percent-encoded variants of block-range queries (e.g., `/api/v1/blocks?limit=1%30`, `/api/v1/blocks?limit=%31%30`, etc.) can saturate the database connection pool, causing legitimate queries to queue or time out. This directly delays the availability of fresh block data to all clients — the cache is never warm for any canonical path because the attacker continuously displaces entries with encoded-key variants. The severity is **High**: no authentication, no rate-limit bypass needed, and the attack is trivially scriptable.

### Likelihood Explanation
The attack requires zero privileges, no special headers, and no knowledge of internal state — only the ability to send HTTP GET requests with percent-encoded query parameters. Any public-facing deployment is exposed. The technique is well-known (HTTP cache poisoning via URL normalization) and the missing normalizer is even documented in the source code itself (issue 9113 reference at line 149), confirming the gap has been known and unaddressed.

### Recommendation
Before hashing, normalize `req.originalUrl` by percent-decoding and re-encoding it canonically. The minimal fix is:

```js
const cacheKeyGenerator = (req) => {
  // Decode then re-encode to canonical form to prevent encoding-variant cache bypass
  const normalized = new URL(req.originalUrl, 'http://localhost').pathname +
    '?' + new URLSearchParams(new URL(req.originalUrl, 'http://localhost').searchParams).toString();
  return crypto.createHash('md5').update(normalized).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

Alternatively, accelerate the planned integration of the request normalizer referenced in issue 9113. Also consider sorting query parameters canonically so `?a=1&b=2` and `?b=2&a=1` map to the same key.

### Proof of Concept

```bash
# Step 1: Warm the cache with the canonical URL
curl -s "http://mirror-node/api/v1/blocks?limit=10" > /dev/null

# Step 2: Bypass the cache with a percent-encoded equivalent
# %31%30 decodes to "10" — same query, different raw URL, different MD5 key
curl -v "http://mirror-node/api/v1/blocks?limit=%31%30"
# Observe: X-Cache: MISS (or equivalent), full DB latency, no cache hit

# Step 3: Automate to starve the cache
for i in $(seq 1 1000); do
  # Rotate encoding of a single character to generate unique cache keys
  curl -s "http://mirror-node/api/v1/blocks?limit=1%30&offset=$i" > /dev/null &
done
# Result: Redis fills with one-off encoded keys; canonical queries never hit cache;
# DB query rate spikes proportionally; block data latency increases under load.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/middleware/responseCacheHandler.js (L90-117)
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
```

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
