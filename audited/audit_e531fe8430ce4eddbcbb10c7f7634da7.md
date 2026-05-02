### Title
Cache Key Excludes Authorization Header — Authenticated User's Elevated-Limit Response Served to Unauthenticated Users

### Summary
`responseCacheCheckHandler()` generates cache keys using only `req.originalUrl` (MD5 hash), with no inclusion of the `Authorization` header. Because `authHandler` grants authenticated users a higher per-user result `limit`, a response generated under elevated privileges gets stored and later served verbatim to any unauthenticated user who requests the identical URL, bypassing the default result-count cap entirely.

### Finding Description

**Middleware execution order** (`rest/server.js` lines 86–97):
1. `authHandler` (line 86) — authenticates the request and, for valid credentials, calls `httpContext.set(userLimitLabel, user.limit)` to raise the effective result limit above the global default.
2. `responseCacheCheckHandler` (line 97) — checks Redis; on a cache hit, immediately writes the stored response to the client and returns, skipping all downstream route handlers.

**Cache key generation** (`rest/middleware/responseCacheHandler.js` lines 151–153):
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```
The key is derived exclusively from `req.originalUrl`. The `Authorization` header is never read or hashed.

**Cache population** (lines 90–118): When a privileged user's request is processed normally (cache miss), the route handler enforces `user.limit` (e.g. 10) instead of the global max (e.g. 2). The resulting response — containing up to 10 records — is stored in Redis under the URL-only key.

**Cache hit for unprivileged user** (lines 43–87): A subsequent unauthenticated request to the same URL hits the cache. `responseCacheCheckHandler` reads the stored `CachedApiResponse`, sets headers (including `cache-control: public, max-age=<ttl>`), and sends the body directly. No limit re-evaluation occurs; the unauthenticated user receives the full privileged response.

**Why `authHandler` does not protect here**: `authHandler` runs and correctly sets no elevated limit for the unauthenticated request, but `responseCacheCheckHandler` short-circuits the pipeline before any route handler that would enforce the limit is ever reached.

### Impact Explanation
An unauthenticated (zero-privilege) user can receive a response containing more records than the system's access-control policy permits for their tier. The `users[].limit` configuration is the sole mechanism for differentiating data-volume access between user classes; the cache completely nullifies it for any URL that a privileged user has previously requested. The `cache-control: public` header written at line 60 additionally instructs downstream proxies and CDNs to cache and re-serve the elevated response to further unauthenticated clients, amplifying the exposure.

### Likelihood Explanation
Exploitation requires no special tooling or privileges. An attacker needs only to:
- Know (or guess) a URL that a privileged user has recently requested — trivially achievable since the API URL space is documented and finite.
- Issue an identical GET request within the Redis TTL window.

The attack is fully passive from the attacker's perspective, repeatable on every cache refresh cycle, and leaves no distinguishing trace beyond a normal HTTP request in access logs.

### Recommendation
Include a normalized representation of the authentication identity (or privilege tier) in the cache key. The simplest correct fix is to hash the `Authorization` header value alongside the URL:

```js
const cacheKeyGenerator = (req) => {
  const authHeader = req.get('authorization') || '';
  return crypto.createHash('md5')
    .update(req.originalUrl + '\0' + authHeader)
    .digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

Alternatively, maintain separate cache namespaces per user tier (e.g. `anonymous`, per-username), or set `cache-control: private` on responses generated under elevated limits so they are never stored in the shared Redis cache.

### Proof of Concept

**Preconditions**: caching enabled (`config.cache.response.enabled = true`, `config.redis.enabled = true`); a configured privileged user, e.g. `premium:secret` with `limit: 10`; global `response.limit.default = 1`, `response.limit.max = 2`.

**Steps**:

1. Send a privileged request to populate the cache:
   ```
   GET /api/v1/transactions?limit=10
   Authorization: Basic cHJlbWl1bTpzZWNyZXQ=
   ```
   Response: 200 with 10 transaction objects. Redis now stores this response under `MD5("/api/v1/transactions?limit=10") + "-v1"`.

2. Within the Redis TTL, send an unauthenticated request to the same URL:
   ```
   GET /api/v1/transactions?limit=10
   ```
   Expected (without cache): 2 transaction objects (capped at global max).
   **Actual**: 200 with 10 transaction objects — the privileged cached response — served by `responseCacheCheckHandler` before any limit enforcement runs.

**Relevant code locations**:
- Cache key: [1](#0-0) 
- Cache hit short-circuit: [2](#0-1) 
- `public` cache-control header written on cache hit: [3](#0-2) 
- Middleware order (auth before cache check): [4](#0-3) 
- Auth sets elevated limit, not enforced on cache hit: [5](#0-4)

### Citations

**File:** rest/middleware/responseCacheHandler.js (L43-87)
```javascript
  const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);

  if (!cachedTtlAndValue) {
    res.locals[responseCacheKeyLabel] = responseCacheKey;
    return;
  }

  const {ttl: redisTtl, value: redisValue} = cachedTtlAndValue;
  const cachedResponse = Object.assign(new CachedApiResponse(), redisValue);
  const conditionalHeader = req.get(CONDITIONAL_HEADER);
  const clientCached = conditionalHeader && conditionalHeader === cachedResponse.headers[ETAG_HEADER]; // 304
  const statusCode = clientCached ? httpStatusCodes.UNMODIFIED.code : cachedResponse.statusCode;
  const isHead = req.method === 'HEAD';

  let body;
  const headers = {
    ...cachedResponse.headers,
    ...{[CACHE_CONTROL_HEADER]: `public, max-age=${redisTtl}`},
  };

  if (isHead || clientCached) {
    if (clientCached) {
      delete headers[contentTypeHeader];
    } else {
      // For HEAD requests when status code is not 304, negotiate the encoding and set corresponding headers
      negotiate(cachedResponse, req, res);
    }
  } else {
    const useCompressed = negotiate(cachedResponse, req, res);
    body = useCompressed ? cachedResponse.getBody() : cachedResponse.getUncompressedBody();
  }

  res.set(headers);
  res.status(statusCode);
  if (body !== undefined) {
    res.send(body);
  } else {
    res.end();
  }

  const elapsed = Date.now() - startTime;
  logger.info(
    `${req.ip} ${req.method} ${req.originalUrl} from cache (ttl: ${redisTtl}) in ${elapsed} ms: ${statusCode}`
  );
};
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/server.js (L85-98)
```javascript
// authentication middleware - must come after httpContext and requestLogger
app.useExt(authHandler);

// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}

// Check for cached response
if (applicationCacheEnabled) {
  logger.info('Response caching is enabled');
  app.useExt(responseCacheCheckHandler);
}
```

**File:** rest/middleware/authHandler.js (L32-35)
```javascript
  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
```
