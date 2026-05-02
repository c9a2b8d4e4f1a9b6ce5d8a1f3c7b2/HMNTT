I have verified all the code references in the claim. Let me confirm the key facts:

All code references have been verified against the actual repository. Every factual claim in the submission is accurate.

---

Audit Report

## Title
Cache Key Excludes Authorization Header — Authenticated User's Elevated-Limit Response Served to Unauthenticated Users

## Summary
`responseCacheCheckHandler` generates Redis cache keys using only an MD5 hash of `req.originalUrl`. Because `authHandler` grants authenticated users a higher per-request result `limit` via `httpContext`, a response produced under elevated privileges is stored and later served verbatim to any unauthenticated user who requests the identical URL, completely bypassing the default result-count cap.

## Finding Description

**Middleware execution order** is confirmed in `rest/server.js`:
- Line 86: `authHandler` runs first. For valid credentials with a configured limit, it calls `httpContext.set(userLimitLabel, user.limit)`.
- Line 97: `responseCacheCheckHandler` runs after. On a cache hit it immediately writes the stored response to the client and returns, short-circuiting all downstream route handlers. [1](#0-0) 

**Cache key generation** in `rest/middleware/responseCacheHandler.js` lines 151–153 hashes only `req.originalUrl`. The `Authorization` header is never read or incorporated. [2](#0-1) 

**Limit enforcement** in `rest/utils.js` lines 533–553: `getEffectiveMaxLimit()` reads `httpContext.get(userLimitLabel)` and returns the user's custom limit when set, otherwise the global `responseLimit.max`. `getLimitParamValue()` caps the request's `limit` parameter against this value. For an authenticated user with `limit: 10` and a global max of `2`, the route handler returns up to 10 records. [3](#0-2) 

**Cache population** in `responseCacheUpdateHandler` (lines 90–118): the full response body is stored in Redis under the URL-only key. [4](#0-3) 

**Cache hit for unauthenticated user** (lines 40–87): `responseCacheCheckHandler` retrieves the stored `CachedApiResponse`, sets `cache-control: public, max-age=<ttl>`, and sends the body directly. No limit re-evaluation occurs. [5](#0-4) 

**Root cause**: The cache key namespace is not partitioned by privilege tier. The `authHandler` correctly sets no elevated limit for unauthenticated requests, but `responseCacheCheckHandler` short-circuits the pipeline before any route handler that would enforce the limit is ever reached. [6](#0-5) 

## Impact Explanation
An unauthenticated user receives a response containing more records than the system's access-control policy permits for their tier. The `users[].limit` configuration (validated and parsed in `rest/config.js` lines 188–216) is the sole mechanism for differentiating data-volume access between user classes; the cache completely nullifies it for any URL a privileged user has previously requested. [7](#0-6) 

The `cache-control: public` header written at line 60 additionally instructs downstream proxies and CDNs to cache and re-serve the elevated response to further unauthenticated clients, amplifying the exposure beyond the single Redis TTL window. [8](#0-7) 

## Likelihood Explanation
Exploitation requires no special tooling or privileges. The API URL space is fully documented and finite. An attacker needs only to issue a GET request to any URL that a privileged user has recently requested within the Redis TTL window. The attack is fully passive, repeatable on every cache refresh cycle, and indistinguishable from a normal HTTP request in access logs.

The integration test suite in `rest/__tests__/integration/authentication.test.js` explicitly confirms that unauthenticated requests are capped at the default max and authenticated requests exceed it — the exact differential that the cache collapses. [9](#0-8) 

## Recommendation
Partition the cache key by privilege tier. The simplest correct fix is to append a representation of the effective limit tier to the cache key inside `cacheKeyGenerator`. For example:

```js
const cacheKeyGenerator = (req) => {
  const userLimit = httpContext.get(userLimitLabel) ?? 'default';
  return crypto.createHash('md5')
    .update(req.originalUrl + '|' + userLimit)
    .digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

This ensures responses produced under elevated limits are stored and served only to requests with the same privilege tier. Alternatively, set `cache-control: private` for authenticated responses so they are never stored in shared caches. [10](#0-9) 

## Proof of Concept

**Setup**: configure `response.limit.default=1`, `response.limit.max=2`, and one user with `limit=10`. Populate at least 10 records.

1. **Privileged request (cache miss)**:
   ```
   GET /api/v1/transactions?limit=10
   Authorization: Basic <base64(user:pass)>
   ```
   Response: 10 records. Redis now stores this response under `MD5("/api/v1/transactions?limit=10") + "-v1"`.

2. **Unauthenticated request (cache hit)**:
   ```
   GET /api/v1/transactions?limit=10
   ```
   Response: 10 records — identical to step 1, despite the unauthenticated user being subject to a cap of 2.

The `responseCacheCheckHandler` serves the stored body at step 2 before any route handler runs, so `getLimitParamValue` is never called and the cap is never enforced. [11](#0-10)

### Citations

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

**File:** rest/middleware/responseCacheHandler.js (L40-87)
```javascript
const responseCacheCheckHandler = async (req, res) => {
  const startTime = res.locals[requestStartTime] || Date.now();
  const responseCacheKey = cacheKeyGenerator(req);
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

**File:** rest/middleware/responseCacheHandler.js (L90-116)
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

**File:** rest/utils.js (L533-553)
```javascript
const getEffectiveMaxLimit = () => {
  const userLimit = httpContext.get(userLimitLabel);
  return userLimit !== undefined ? userLimit : responseLimit.max;
};

/**
 * Gets the limit param value, if not exists, return the default; otherwise cap it at max.
 * Note if values is an array, the last one is honored.
 * @param {string[]|string} values Values of the limit param
 * @return {number}
 */
const getLimitParamValue = (values) => {
  let ret = responseLimit.default;
  if (values !== undefined) {
    const value = Array.isArray(values) ? values[values.length - 1] : values;
    const parsed = Number(value);
    const maxLimit = getEffectiveMaxLimit();
    ret = parsed > maxLimit ? maxLimit : parsed;
  }
  return ret;
};
```

**File:** rest/middleware/authHandler.js (L15-36)
```javascript
const authHandler = async (req, res) => {
  const credentials = basicAuth(req);

  if (!credentials) {
    return;
  }

  const user = findUser(credentials.name, credentials.pass);
  if (!user) {
    res.status(httpStatusCodes.UNAUTHORIZED.code).json({
      _status: {
        messages: [{message: 'Invalid credentials'}],
      },
    });
    return;
  }

  if (user.limit !== undefined && user.limit > 0) {
    httpContext.set(userLimitLabel, user.limit);
    logger.debug(`Authenticated user ${user.username} with custom limit ${user.limit}`);
  }
};
```

**File:** rest/config.js (L188-216)
```javascript
const parseUsersConfig = () => {
  const users = getConfig().users || [];

  if (!Array.isArray(users)) {
    throw new InvalidConfigError('users configuration must be an array');
  }

  users.forEach((user, index) => {
    if (!user.username || typeof user.username !== 'string') {
      throw new InvalidConfigError(`users[${index}] must have a username string`);
    }
    if (!user.password || typeof user.password !== 'string') {
      throw new InvalidConfigError(`users[${index}] must have a password string`);
    }
    if (user.limit !== undefined) {
      const limit = parseInt(user.limit, 10);
      if (Number.isNaN(limit) || limit <= 0) {
        throw new InvalidConfigError(`users[${index}].limit must be a positive integer`);
      }
      user.limit = limit;
    }
  });

  const usernames = users.map((u) => u.username);
  const duplicates = usernames.filter((name, index) => usernames.indexOf(name) !== index);
  if (duplicates.length > 0) {
    throw new InvalidConfigError(`Duplicate usernames in users configuration: ${duplicates.join(', ')}`);
  }
};
```

**File:** rest/__tests__/integration/authentication.test.js (L45-83)
```javascript
  test('Unauthenticated request uses default max limit', async () => {
    // create test data
    const transactions = [];
    for (let i = 0; i < 5; i++) {
      transactions.push({
        consensus_timestamp: 1000000000n + BigInt(i),
        payerAccountId: 2,
        type: 14,
      });
    }
    await integrationDomainOps.loadTransactions(transactions);

    const response = await request(server).get('/api/v1/transactions?limit=10');

    expect(response.status).toBe(200);
    expect(response.body.transactions.length).toBeLessThanOrEqual(2); // capped at default max (2)
  });

  test('Authenticated user can exceed default max up to custom limit', async () => {
    // create test data
    const transactions = [];
    for (let i = 0; i < 10; i++) {
      transactions.push({
        consensus_timestamp: 2000000000n + BigInt(i),
        payerAccountId: 2,
        type: 14,
      });
    }
    await integrationDomainOps.loadTransactions(transactions);

    const credentials = Buffer.from(`${testUser.username}:${testUser.password}`).toString('base64');
    const response = await request(server)
      .get('/api/v1/transactions?limit=5')
      .set('Authorization', `Basic ${credentials}`);

    expect(response.status).toBe(200);
    expect(response.body.transactions.length).toBeGreaterThan(2); // exceeds default max
    expect(response.body.transactions.length).toBeLessThanOrEqual(5); // capped at custom limit (5)
  });
```
