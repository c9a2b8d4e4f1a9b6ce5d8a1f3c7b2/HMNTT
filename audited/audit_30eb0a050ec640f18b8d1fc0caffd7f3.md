### Title
Cache Bypass via Arbitrary Query Parameter Injection in `cacheKeyGenerator()`

### Summary
The `cacheKeyGenerator()` function in `rest/middleware/responseCacheHandler.js` derives the Redis cache key by MD5-hashing `req.originalUrl` verbatim, with no normalization or filtering of unknown query parameters. An unprivileged attacker can append an arbitrary, ever-changing query parameter (e.g., `?_=<random>`) to every request, producing a unique cache key per request, forcing every request to miss the cache and hit the backend database. The code itself acknowledges this gap with a TODO comment referencing a future normalizer that has not been integrated.

### Finding Description
**Exact code location:** `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, lines 151–153.

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` is the raw, unmodified URL string including the full query string as sent by the client. Any change to the query string — including appending an unknown parameter — produces a different MD5 digest and therefore a different Redis key.

**Root cause / failed assumption:** The code assumes that clients will only send known, valid query parameters. The comment at line 149 explicitly acknowledges the absence of normalization:

> `path?query - In the future, this will utilize Edwin's request normalizer (9113).`

**Why existing checks fail:**

- `normalizeRequestQueryParams()` in `rest/middleware/requestNormalizer.js` (lines 35–59) does exist and strips unknown parameters — but it is **never called** in the middleware pipeline. A `grep` across the entire codebase shows it is only referenced in its own test file (`rest/__tests__/middleware/requestNormalizer.test.js`). It is not imported in `server.js` and is not invoked before `responseCacheCheckHandler`.
- `requestQueryParser` in `rest/middleware/requestHandler.js` (lines 38–69) only lowercases keys and canonicalizes `order`/`result` values; it does not strip unknown parameters.
- The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives in the `web3` Java service, not in the REST Node.js service. There is no rate limiting applied to the REST API middleware chain that would block this attack.
- The middleware registration order in `rest/server.js` (lines 94–97) places `responseCacheCheckHandler` before any route handler, meaning the raw `req.originalUrl` is used for cache lookup before any request validation occurs.

**Exploit flow:**

1. Attacker sends `GET /api/v1/accounts?_=1` → cache miss → backend query → response cached under key `md5("/api/v1/accounts?_=1")`.
2. Attacker sends `GET /api/v1/accounts?_=2` → different MD5 → cache miss → backend query → new Redis entry.
3. Repeat with `_=3`, `_=4`, … at high frequency.
4. Every request bypasses the cache and hits the database. Redis accumulates a unique entry per request (each with a TTL of at least 1 second per `DEFAULT_REDIS_EXPIRY`).

### Impact Explanation
- **Cache rendered useless:** The entire purpose of the Redis response cache — shielding the database from repeated identical queries — is defeated.
- **Backend database overload:** All requests that would normally be served from cache now execute full database queries, potentially exhausting connection pools and degrading service for all users.
- **Redis memory exhaustion:** Each unique URL variant is stored as a separate Redis key. A sustained attack with high request rates fills Redis memory, potentially evicting legitimate cache entries or causing Redis OOM errors.
- **Severity: High.** The cache is a primary scalability mechanism for the REST API. Bypassing it under load constitutes a practical denial-of-service against the backend.

### Likelihood Explanation
- **No authentication required.** The REST API is a public mirror node API; any external user can send HTTP requests.
- **Trivially automatable.** A simple script incrementing a counter in a query parameter is sufficient. No special knowledge, credentials, or protocol manipulation is needed.
- **No rate limiting in scope.** The REST Node.js service has no per-IP or per-endpoint rate limiting middleware in its pipeline.
- **Repeatable indefinitely.** The attacker can sustain the attack as long as they can send HTTP requests.

### Recommendation
Integrate `normalizeRequestQueryParams()` into the cache key generation path **before** `responseCacheCheckHandler` runs, so that unknown query parameters are stripped and the normalized URL is used as the cache key input. Concretely:

1. Call `normalizeRequestQueryParams()` (already implemented in `rest/middleware/requestNormalizer.js`) in a middleware that runs before `responseCacheCheckHandler` and stores the normalized URL in `res.locals` or overwrites `req.url`.
2. Modify `cacheKeyGenerator()` to use the normalized URL from `res.locals` instead of `req.originalUrl`.
3. As a defense-in-depth measure, add per-IP rate limiting to the REST API middleware chain.

### Proof of Concept
```bash
# Baseline: warm the cache
curl "https://<mirror-node>/api/v1/accounts?limit=10"

# Attack: bypass cache with unique parameter on every request
for i in $(seq 1 10000); do
  curl -s "https://<mirror-node>/api/v1/accounts?limit=10&_=${i}" &
done
wait
```

Each request produces a unique `req.originalUrl`, a unique MD5 cache key, a Redis cache miss, and a live database query. Redis will accumulate 10,000 distinct cache entries. The backend database receives 10,000 queries that the cache was designed to absorb. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rest/server.js (L94-97)
```javascript
// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
```
