### Title
Cache Stampede DoS via Unbounded Cache-Miss Requests in `responseCacheCheckHandler()`

### Summary
The `responseCacheCheckHandler()` function in `rest/middleware/responseCacheHandler.js` generates cache keys directly from `req.originalUrl` with no request normalization. Because the REST API middleware stack contains zero rate-limiting controls, an unauthenticated attacker can flood transaction endpoints with unique URL variants (e.g., incrementing timestamp query parameters), causing every request to miss the Redis cache and fall through to the PostgreSQL database, exhausting the connection pool and denying service to legitimate users.

### Finding Description
**Code path:**

`rest/middleware/responseCacheHandler.js`, `responseCacheCheckHandler()` (lines 40–87) and `cacheKeyGenerator()` (lines 151–153):

```js
// Line 42-48: cache miss falls through to DB unconditionally
const responseCacheKey = cacheKeyGenerator(req);
const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);
if (!cachedTtlAndValue) {
  res.locals[responseCacheKeyLabel] = responseCacheKey;
  return;   // <-- proceeds to DB handler with no guard
}

// Line 151-153: key is raw URL hash — no normalization
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**Root cause — two compounding weaknesses:**

1. **No rate limiting anywhere in the REST service.** `rest/package.json` contains no rate-limiting dependency (`express-rate-limit`, `express-slow-down`, etc. are absent). The middleware chain in `rest/server.js` (lines 67–98) is: `urlencoded → json → cors → compression → httpContext → requestLogger → authHandler → metricsHandler → responseCacheCheckHandler`. There is no rate-limiting step. The throttling that does exist (`web3/src/main/java/…/ThrottleConfiguration.java`) belongs to the separate Java `web3` service and has no effect on the Node.js REST API.

2. **Cache key is the raw URL hash with no normalization.** The comment at line 149 explicitly acknowledges: *"In the future, this will utilize Edwin's request normalizer (9113)."* Until that normalizer is applied, `?timestamp=gt:1000000000.000000001` and `?timestamp=gt:1000000000.000000002` produce different MD5 keys and are treated as entirely separate cache entries.

**Why existing checks fail:**
- `authHandler.js` (lines 15–36) only validates Basic Auth credentials and sets a per-user *result-count* limit (`user.limit`). It imposes no request-rate limit and is entirely skipped for unauthenticated requests (line 18–20: `if (!credentials) return`).
- Redis caching is only effective for repeated identical URLs. Unique URLs bypass it completely.
- There is no mutex, coalescing, or "only-one-inflight" guard for concurrent cache misses on the same or different keys.

### Impact Explanation
Every cache-miss request proceeds to a PostgreSQL query against the `transaction` table (a high-cardinality, write-heavy table). A sustained flood of unique-URL requests exhausts the `pg` connection pool, causing legitimate queries to queue and time out. The result is full denial of service for all REST API consumers. Because the transactions endpoint supports rich filter parameters (`timestamp`, `account.id`, `transactiontype`, `result`, etc.), the attacker has an effectively unlimited supply of unique cache-busting URLs without needing any special knowledge of the system.

### Likelihood Explanation
The attack requires no credentials, no special tooling beyond `curl` or `ab`, and no knowledge of internal state. Any internet-accessible deployment is exposed. The attack is trivially repeatable and automatable. The only practical barrier is network bandwidth to the server, which is low given that each request is a small HTTP GET.

### Recommendation
1. **Add per-IP rate limiting** as the first substantive middleware in `rest/server.js`, before `responseCacheCheckHandler`, using `express-rate-limit` or equivalent.
2. **Implement request normalization** (the already-planned issue #9113) so that semantically equivalent queries share a single cache key, reducing the attack surface for cache-busting.
3. **Add cache-miss coalescing** (a "thundering herd" lock in Redis) so that concurrent misses for the same key result in only one DB query.
4. **Set explicit PostgreSQL pool limits** with a short queue timeout so that a flood does not cascade into full process starvation.

### Proof of Concept
```bash
# Flood /api/v1/transactions with unique timestamp suffixes — no auth required
for i in $(seq 1 5000); do
  curl -s "https://<mirror-node>/api/v1/transactions?timestamp=gt:1000000000.$(printf '%09d' $i)" &
done
wait
# Each request generates a unique MD5 cache key → cache miss → DB query
# PostgreSQL connection pool exhausted; legitimate requests receive 503/timeout
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/server.js (L67-98)
```javascript
// middleware functions, Prior to v0.5 define after sets
app.use(
  express.urlencoded({
    extended: false,
  })
);
app.use(express.json());
app.use(cors());

if (config.response.compression) {
  logger.info('Response compression is enabled');
  app.use(compression());
}

// logging middleware
app.use(httpContext.middleware);
app.useExt(requestLogger);

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

**File:** rest/middleware/authHandler.js (L15-20)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }
```

**File:** rest/package.json (L22-49)
```json
  "dependencies": {
    "@bufbuild/protobuf": "2.12.0",
    "@godaddy/terminus": "4.12.1",
    "@opentelemetry/api": "^1.9.0",
    "@opentelemetry/exporter-prometheus": "^0.215.0",
    "@opentelemetry/sdk-metrics": "^2.6.1",
    "asn1js": "3.0.10",
    "basic-auth": "2.0.1",
    "compression": "1.8.1",
    "cors": "2.8.6",
    "express": "5.2.1",
    "express-http-context": "2.0.1",
    "express-openapi-validator": "5.6.2",
    "extend": "3.0.2",
    "ioredis": "5.10.1",
    "js-yaml": "4.1.1",
    "json-bigint": "1.0.0",
    "lodash": "4.18.1",
    "negotiator": "1.0.0",
    "parse-duration": "2.1.6",
    "pg": "8.20.0",
    "pg-range": "1.1.2",
    "qs": "6.15.1",
    "quick-lru": "7.3.0",
    "rfc4648": "1.5.4",
    "sql-formatter": "15.7.3",
    "swagger-ui-express": "5.0.1",
    "tsscmp": "1.0.6"
```
