### Title
Cache Key Fragmentation via Unordered Query Parameters in `cacheKeyGenerator()`

### Summary
The `cacheKeyGenerator()` function in `rest/middleware/responseCacheHandler.js` hashes `req.originalUrl` verbatim using MD5, without normalizing query parameter ordering. Because `req.originalUrl` preserves the raw client-supplied URL, semantically identical requests with differently ordered parameters (e.g., `?limit=25&order=asc` vs `?order=asc&limit=25`) produce distinct cache keys, causing cache fragmentation. A `requestNormalizer.js` module exists that would fix this, but the code itself explicitly acknowledges it has not yet been integrated.

### Finding Description
**Exact code location:** `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator()`, line 151–153:

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
``` [1](#0-0) 

The comment immediately above this function (line 149) explicitly acknowledges the gap:

> *"In the future, this will utilize Edwin's request normalizer (9113)."* [2](#0-1) 

`req.originalUrl` in Express.js is the raw, unmodified URL string as received from the client. Query parameter ordering is fully attacker-controlled. Two requests that are semantically identical to the Hashgraph mirror node backend:

```
GET /api/v1/accounts?limit=25&order=asc
GET /api/v1/accounts?order=asc&limit=25
```

produce different MD5 digests and therefore different Redis keys, so neither request benefits from the other's cached response.

A `normalizeRequestQueryParams()` function exists in `rest/middleware/requestNormalizer.js` that sorts parameters and adds defaults: [3](#0-2) 

However, `requestNormalizer.js` is **not exported** from `rest/middleware/index.js` and is **not called** from `cacheKeyGenerator()` or anywhere in the cache middleware path: [4](#0-3) 

The normalizer is only exercised in its own isolated test file (`rest/__tests__/middleware/requestNormalizer.test.js`), confirming it is not wired into the production cache key path.

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions?timestamp=gte:1000&limit=25&order=desc` — this populates Redis under key `md5("/api/v1/transactions?timestamp=gte:1000&limit=25&order=desc")-v1`.
2. Attacker (or any client) sends `GET /api/v1/transactions?order=desc&limit=25&timestamp=gte:1000` — `cacheKeyGenerator` produces a different MD5 hash; Redis returns a miss.
3. The backend is queried again; the response is stored under a second distinct Redis key.
4. Repeating with N permutations of K parameters creates up to K! distinct cache entries for the same logical query, exhausting Redis memory and forcing repeated backend queries.

### Impact Explanation
The direct impact is **cache fragmentation and cache-bypass DoS**:
- Redis memory is consumed by duplicate entries for semantically identical queries.
- Cached authentic responses are bypassed, forcing repeated database queries against the mirror node's PostgreSQL backend.
- Under sustained parameter-permutation flooding, Redis eviction pressure can cause legitimate cached entries to be evicted, amplifying backend load.
- The attacker cannot inject false Hashgraph history data through this vector — responses are always fetched from the legitimate backend. The integrity of individual responses is not compromised, but availability and cache effectiveness are.

Severity: **Medium** (availability/performance impact; no data integrity compromise).

### Likelihood Explanation
- **No privileges required.** Any unauthenticated HTTP client can exploit this.
- **Trivially automatable.** A script that permutes query parameters across all public REST endpoints requires no special knowledge.
- **Repeatable indefinitely.** There is no rate-limiting or deduplication at the cache key layer that would prevent sustained exploitation.
- The number of exploitable endpoints is large; the OpenAPI spec defines many multi-parameter endpoints (accounts, transactions, contracts, tokens, etc.), each with multiple sortable parameters.

### Recommendation
Integrate `normalizeRequestQueryParams()` into `cacheKeyGenerator()` before hashing. The normalizer already sorts non-order-sensitive parameters and adds defaults. The cache key should be computed from the normalized URL, not `req.originalUrl`:

```js
import {normalizeRequestQueryParams} from './requestNormalizer.js';

const cacheKeyGenerator = (req) => {
  const normalizedUrl = normalizeRequestQueryParams(
    req.openapi?.openApiRoute,
    req.path,
    req.query
  );
  return crypto.createHash('md5').update(normalizedUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

This is exactly what the existing TODO comment (issue 9113) describes. Until this is done, every distinct parameter permutation creates a separate cache entry.

### Proof of Concept
```bash
# Populate cache with canonical ordering
curl "https://<mirror-node>/api/v1/accounts?limit=25&order=asc&balance=true"

# Bypass cache with reordered parameters (cache miss, backend re-queried)
curl "https://<mirror-node>/api/v1/accounts?balance=true&order=asc&limit=25"
curl "https://<mirror-node>/api/v1/accounts?order=asc&balance=true&limit=25"
curl "https://<mirror-node>/api/v1/accounts?balance=true&limit=25&order=asc"
# ... up to 3! = 6 permutations, each a distinct Redis key, each a cache miss

# Automate across all endpoints to exhaust Redis and force continuous DB load:
for perm in $(python3 -c "import itertools; params=['limit=25','order=desc','timestamp=gte:1000']; [print('&'.join(p)) for p in itertools.permutations(params)]"); do
  curl -s "https://<mirror-node>/api/v1/transactions?$perm" -o /dev/null &
done
```

Each permutation is confirmed to produce a distinct MD5 hash by the verbatim `req.originalUrl` hashing at line 152 of `responseCacheHandler.js`, with no normalization applied before or after. [1](#0-0)

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

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```
