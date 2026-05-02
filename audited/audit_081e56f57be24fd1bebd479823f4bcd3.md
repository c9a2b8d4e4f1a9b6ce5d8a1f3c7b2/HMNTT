### Title
Cache Key Pollution via Unnormalized `req.originalUrl` in `cacheKeyGenerator()` — Fragment Identifiers and Query Parameter Ordering Enable Unprivileged Cache Busting

### Summary
`cacheKeyGenerator()` computes the Redis cache key as an MD5 hash of `req.originalUrl` verbatim, with no URL normalization. Because Node.js's HTTP parser passes the raw request-target to Express without stripping fragment identifiers or enforcing query-parameter ordering, any unprivileged caller using a raw HTTP client can craft URLs that route identically to a canonical resource but hash to a different cache key, causing perpetual cache misses and forced database hits. The code itself acknowledges the normalization gap ("In the future, this will utilize Edwin's request normalizer (9113)") but the normalizer is never wired into `cacheKeyGenerator`.

### Finding Description

**Exact code path:**

`rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, line 151–153:

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` is the raw URL string as received from Node.js's HTTP parser. It is never normalized before being hashed.

**Root cause — two independent sub-issues:**

1. **Fragment identifiers (`#`).**  
   HTTP browsers strip `#fragment` before sending a request, so it never reaches the server. However, Node.js's HTTP parser (`llhttp`) is lenient: it passes the raw request-target to the application unchanged. Express sets `req.originalUrl = req.url` (the raw value). Express routing uses `parseurl`, which calls `url.parse()` and separates `pathname` from `hash`, so the route *matches correctly* — but `req.originalUrl` still contains `#fragment`. A raw HTTP client (curl, Python `requests`, any custom tool) can therefore send:
   ```
   GET /api/v1/transactions/0.0.1-1234567890-1#x HTTP/1.1
   ```
   Express routes to `transactions.getTransactionsByIdOrHash` normally, but `cacheKeyGenerator` hashes `/api/v1/transactions/0.0.1-1234567890-1#x`, which differs from the canonical key for `/api/v1/transactions/0.0.1-1234567890-1`.

2. **Query parameter ordering.**  
   `/api/v1/transactions?limit=10&order=asc` and `/api/v1/transactions?order=asc&limit=10` are semantically identical but produce different MD5 hashes. No browser or HTTP library guarantees parameter order. The existing `requestNormalizer.js` (`normalizeRequestQueryParams`) sorts and canonicalizes parameters but is **never called** from `cacheKeyGenerator` — it is only used in tests.

**Why existing checks fail:**

- `requestQueryParser` (line 60, `server.js`) lowercases keys and canonicalizes a few values (`order`, `result`) but does **not** sort parameters and does **not** strip fragments.
- `requestNormalizer.js` exists and is correct, but is not integrated into the cache key path.
- `responseCacheCheckHandler` is registered globally (line 97, `server.js`) before any route handler, so it runs on every request with no per-route filtering.
- There is no input validation that rejects URLs containing `#`.

### Impact Explanation

An unprivileged attacker can:

1. **Bust the cache for any transaction or resource** by appending `#<random>` or reordering query parameters, forcing every request to hit the database. With a scripted loop of unique fragments (`#a`, `#b`, `#c`, …), the attacker can ensure the cache is never warm for a targeted resource.
2. **Pollute Redis** with an unbounded number of duplicate cache entries (one per unique URL variant), consuming memory and evicting legitimate entries.
3. **Amplify database load** proportionally to the request rate, potentially causing a denial-of-service against the PostgreSQL backend.
4. **Infer timing side-channels**: cache hits return in microseconds; cache misses incur a full DB round-trip. By observing response latency, an attacker can determine whether a given transaction ID was recently queried by a legitimate user (cache warm vs. cold), leaking access-pattern metadata.

Severity: **Medium–High** (availability impact is high; confidentiality impact is low but present via timing).

### Likelihood Explanation

- **No authentication required.** The cache middleware runs before `authHandler` only in the check path; any public API caller is affected.
- **No special tooling required for query-parameter reordering** — standard HTTP clients (curl, Python, JavaScript `fetch`) allow arbitrary parameter ordering.
- **Fragment injection requires a raw HTTP client** (not a browser), but curl suffices: `curl 'http://host/api/v1/transactions/0.0.1-1234567890-1#x'`. This is trivially scriptable.
- The attack is **repeatable and stateless** — each request with a novel fragment or parameter permutation independently triggers a cache miss.

### Recommendation

1. **Normalize `req.originalUrl` before hashing.** Strip the fragment component and sort/canonicalize query parameters. The already-written `normalizeRequestQueryParams` in `rest/middleware/requestNormalizer.js` should be wired into `cacheKeyGenerator`:

   ```js
   import {normalizeRequestQueryParams} from './requestNormalizer.js';

   const cacheKeyGenerator = (req) => {
     // Strip fragment, then normalize path+query
     const urlWithoutFragment = req.originalUrl.split('#')[0];
     const normalized = normalizeRequestQueryParams(
       req.openapi?.openApiRoute,
       req.path,
       req.query
     );
     return crypto.createHash('md5').update(normalized).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
   };
   ```

2. **Reject or sanitize URLs containing `#`** at the HTTP layer (e.g., nginx `return 400` for request URIs containing `#`) to prevent the fragment from ever reaching Node.js.

3. **Add a test case** to `responseCacheHandler.test.js` asserting that `cacheKeyGenerator` returns the same key for URLs that differ only in fragment or parameter order.

### Proof of Concept

**Prerequisites:** Mirror Node REST API running with Redis cache enabled.

**Step 1 — Warm the cache with the canonical URL:**
```bash
curl -s http://localhost:5551/api/v1/transactions/0.0.1-1234567890-1
# Response served from DB; cached under MD5("/api/v1/transactions/0.0.1-1234567890-1")
```

**Step 2 — Send the same request with a fragment identifier:**
```bash
curl -s --path-as-is 'http://localhost:5551/api/v1/transactions/0.0.1-1234567890-1#x'
# req.originalUrl = "/api/v1/transactions/0.0.1-1234567890-1#x"
# Cache key = MD5("/api/v1/transactions/0.0.1-1234567890-1#x") → CACHE MISS → DB hit
```

**Step 3 — Confirm cache miss via timing or logs:**
```
# server log will show: "GET /api/v1/transactions/0.0.1-1234567890-1#x ... 200" (no "from cache")
```

**Step 4 — Loop to sustain cache busting:**
```bash
for i in $(seq 1 1000); do
  curl -s --path-as-is "http://localhost:5551/api/v1/transactions/0.0.1-1234567890-1#$i" > /dev/null
done
# 1000 unique cache keys stored in Redis; 1000 DB queries forced
```

**Step 5 — Query parameter ordering variant (no special flags needed):**
```bash
# Canonical (cached):
curl 'http://localhost:5551/api/v1/transactions?limit=10&order=asc'
# Reordered (cache miss):
curl 'http://localhost:5551/api/v1/transactions?order=asc&limit=10'
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/server.js (L94-98)
```javascript
// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/middleware/requestNormalizer.js (L35-59)
```javascript
const normalizeRequestQueryParams = (openApiRoute, path, query) => {
  const openApiParameters = openApiMap.get(openApiRoute);
  if (isEmpty(openApiParameters)) {
    return isEmpty(query) ? path : path + '?' + querystring.stringify(query);
  }

  let normalizedQuery = '';
  for (const param of openApiParameters) {
    const name = param.parameterName;
    const value = query[name];
    let normalizedValue = '';
    if (value !== undefined) {
      normalizedValue = Array.isArray(value) ? getNormalizedArrayValue(name, value) : value;
    } else if (param?.defaultValue !== undefined) {
      // Add the default value to the query parameter
      normalizedValue = param.defaultValue;
    }

    if (!isEmpty(normalizedValue)) {
      normalizedQuery = appendToQuery(normalizedQuery, name + '=' + normalizedValue);
    }
  }

  return isEmpty(normalizedQuery) ? path : path + '?' + normalizedQuery;
};
```
