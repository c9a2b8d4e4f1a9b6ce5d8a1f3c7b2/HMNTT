### Title
Cache Key Fragmentation via Unsorted Query Parameters in `cacheKeyGenerator()`

### Summary
`cacheKeyGenerator()` in `rest/middleware/responseCacheHandler.js` hashes `req.originalUrl` directly without normalizing query parameter order, causing semantically identical requests with differently-ordered parameters to produce distinct Redis cache keys. An unprivileged external attacker can exploit this to bypass the cache entirely, forcing repeated backend database queries for every permutation of query parameters. The developers explicitly acknowledge this gap in a code comment referencing a future fix.

### Finding Description

**Exact code location:**

`rest/middleware/responseCacheHandler.js`, lines 151–153:
```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

The comment immediately above (lines 148–149) explicitly acknowledges the missing normalization:
```
*   path?query - In the future, this will utilize Edwin's request normalizer (9113).
```

**Root cause:** `req.originalUrl` preserves the raw query string exactly as sent by the client, including parameter order. Two requests that are semantically identical but differ only in parameter ordering produce different MD5 hashes and therefore different Redis keys.

**Middleware pipeline (confirmed via `rest/server.js`):**
- Line 97: `responseCacheCheckHandler` is registered **before** any route handlers.
- Lines 101–133: Route handlers execute.
- Line 140: `responseCacheUpdateHandler` is registered **after** route handlers.

`requestNormalizer.js` (`normalizeRequestQueryParams`) exists but is **never registered as middleware** in `server.js`. It is only called internally within route handlers after the cache check has already occurred, and it does not mutate `req.originalUrl`.

`requestQueryParser` (registered at line 60 via `app.set('query parser', requestQueryParser)`) only lowercases parameter keys and certain values — it does not sort parameters and does not affect `req.originalUrl`.

**Exploit flow:**
1. Attacker identifies any API endpoint accepting multiple query parameters (e.g., `/api/v1/accounts?limit=25&order=asc`).
2. Attacker sends requests cycling through all permutations of those parameters (e.g., `?order=asc&limit=25`).
3. Each permutation produces a unique MD5 hash → unique Redis key → cache miss → full backend database query executed.
4. Attacker repeats continuously, ensuring no permutation ever gets a cache hit.

### Impact Explanation
The caching layer's primary purpose is to absorb repeated identical queries and protect the backend database. By fragmenting the cache across N! permutations of N query parameters, an attacker nullifies this protection entirely for targeted endpoints. For endpoints with 5 parameters, 120 distinct cache keys can be generated. Each cache miss triggers a full database query. This constitutes a low-cost, high-amplification DoS vector against the backend database with no rate limiting or authentication barrier at the cache layer.

### Likelihood Explanation
No privileges, authentication, or special knowledge are required. The attack is trivially automatable with a simple script that cycles through parameter permutations. The public mirror node REST API is internet-facing by design. The `DEFAULT_REDIS_EXPIRY` of 1 second (line 24) means cache entries expire quickly, making sustained fragmentation easy to maintain. The developers' own comment confirms awareness of the gap, indicating it is a real, unmitigated condition in the current codebase.

### Recommendation
Integrate `normalizeRequestQueryParams` from `rest/middleware/requestNormalizer.js` into `cacheKeyGenerator()` so the cache key is derived from the normalized URL rather than `req.originalUrl`. Specifically:

```js
const cacheKeyGenerator = (req) => {
  const normalizedUrl = normalizeRequestQueryParams(req.openapi?.openApiRoute, req.path, req.query);
  return crypto.createHash('md5').update(normalizedUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

This is exactly what the existing comment at line 148–149 anticipates. Additionally, consider applying parameter-order normalization at the middleware level (before `responseCacheCheckHandler`) so `req.originalUrl` itself is canonical.

### Proof of Concept

```bash
# Both requests are semantically identical but produce different cache keys

# Request 1 - populates cache key A
curl "https://<mirror-node>/api/v1/accounts?limit=25&order=asc"

# Request 2 - different parameter order → cache MISS → new backend query
curl "https://<mirror-node>/api/v1/accounts?order=asc&limit=25"

# Automated fragmentation loop (bash)
while true; do
  curl -s "https://<mirror-node>/api/v1/accounts?limit=25&order=asc" &
  curl -s "https://<mirror-node>/api/v1/accounts?order=asc&limit=25" &
  wait
done
```

Each iteration guarantees cache misses for both permutations, doubling backend query load. With more parameters, the amplification factor grows factorially. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/middleware/requestHandler.js (L38-68)
```javascript
const requestQueryParser = (queryString) => {
  const merge = (current, next) => {
    if (!Array.isArray(current)) {
      current = [current];
    }

    if (Array.isArray(next)) {
      current.push(...next);
    } else {
      current.push(next);
    }

    return current;
  };

  // parse first to benefit from qs query handling
  const parsedQueryString = qs.parse(queryString, queryOptions);

  const caseInsensitiveQueryString = {};
  for (const [key, value] of Object.entries(parsedQueryString)) {
    const lowerKey = key.toLowerCase();
    const canonicalValue = canonicalizeValue(lowerKey, value);
    if (lowerKey in caseInsensitiveQueryString) {
      // handle repeated values, merge into an array
      caseInsensitiveQueryString[lowerKey] = merge(caseInsensitiveQueryString[lowerKey], canonicalValue);
    } else {
      caseInsensitiveQueryString[lowerKey] = canonicalValue;
    }
  }

  return caseInsensitiveQueryString;
```
