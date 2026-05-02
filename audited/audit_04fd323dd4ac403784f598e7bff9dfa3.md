### Title
Cache Key Bypass via Query Parameter Order Permutation on `/api/v1/transactions`

### Summary
The `cacheKeyGenerator` function in `rest/middleware/responseCacheHandler.js` derives the Redis cache key by MD5-hashing `req.originalUrl` verbatim, with no normalization of query parameter order. An unauthenticated attacker can cycle through permutations of the same logical query (e.g., `?limit=10&order=asc` vs `?order=asc&limit=10`) to produce a distinct cache key for each permutation, guaranteeing a cache miss and a fresh database query every time. No rate limiting exists in the REST middleware stack.

### Finding Description
**Exact code location:** `rest/middleware/responseCacheHandler.js`, `cacheKeyGenerator`, lines 151–153.

```js
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

`req.originalUrl` is the raw URL string as sent by the client. Two URLs that differ only in query-parameter order produce different MD5 digests and therefore different Redis keys, even though they are semantically identical and would return the same database result.

The code comment at lines 148–149 explicitly acknowledges this gap:
> `path?query - In the future, this will utilize Edwin's request normalizer (9113).`

**Cache check flow** (`responseCacheCheckHandler`, lines 40–47):
```js
const responseCacheKey = cacheKeyGenerator(req);
const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);
if (!cachedTtlAndValue) {
  res.locals[responseCacheKeyLabel] = responseCacheKey;
  return;   // falls through to DB handler
}
```
A cache miss causes the request to fall through to `transactions.getTransactions` (registered at `server.js` line 132), which executes a full database query against `crypto_transfer`, `token_transfer`, and `transaction` tables.

**No rate limiting:** A search across all REST middleware files (`rest/**/*.js`) finds no `rateLimit`, `throttle`, or equivalent middleware applied to the transactions route or globally.

**Existing checks reviewed and shown insufficient:**
- The OpenAPI validator (`server.js` lines 63–65) validates parameter *values*, not parameter *order*.
- The `authHandler` (`server.js` line 86) performs authentication but the transactions endpoint requires no credentials.
- The cache TTL (`CACHE_CONTROL_REGEX`, line 19) only limits how long a cached entry lives; it does not prevent cache-miss storms.

### Impact Explanation
The `/api/v1/transactions` endpoint queries three large tables (`crypto_transfer`, `token_transfer`, `transaction`). With 7 supported query parameters (`account.id`, `timestamp`, `result`, `type`, `order`, `limit`, `transactionType`), there are up to 5,040 distinct parameter orderings for a single logical query. An attacker sending all permutations in rapid succession forces 5,040 independent database queries while the cache remains effectively unused. Sustained at scale this constitutes a denial-of-service against the database backend, degrading or blocking service for all users.

### Likelihood Explanation
No privileges, API keys, or special network access are required. The attack requires only an HTTP client and knowledge of the public API parameters (documented in `rest/api/v1/openapi.yml`). The permutation space is small enough to enumerate in seconds with a simple script. The attack is fully repeatable and stateless.

### Recommendation
Normalize the cache key before hashing:
1. Parse the query string into key-value pairs.
2. Sort parameters by key (and by value for repeated keys).
3. Reconstruct a canonical query string and hash `path + '?' + canonicalQuery`.

This is already planned (issue 9113 referenced in the comment at line 149). Until implemented, apply a per-IP or global request rate limiter (e.g., `express-rate-limit`) on the `/api/v1/transactions` route as a short-term mitigation.

### Proof of Concept
```bash
# Seed the cache with the canonical URL
curl "https://<mirror-node>/api/v1/transactions?limit=10&order=asc"

# Each of the following bypasses the cache and hits the database directly
curl "https://<mirror-node>/api/v1/transactions?order=asc&limit=10"
curl "https://<mirror-node>/api/v1/transactions?limit=10&order=ASC"   # case variant also misses
curl "https://<mirror-node>/api/v1/transactions?order=desc&limit=10"

# Automated permutation loop (bash)
params=("limit=10" "order=asc" "result=success" "type=credit")
for p1 in "${params[@]}"; do
  for p2 in "${params[@]}"; do
    [[ "$p1" == "$p2" ]] && continue
    curl -s "https://<mirror-node>/api/v1/transactions?${p1}&${p2}" -o /dev/null &
  done
done
wait
# Each unique ordering is a cache miss → separate DB query
```

**Relevant code references:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/server.js (L131-133)
```javascript
// transactions routes
app.getExt(`${apiPrefix}/transactions`, transactions.getTransactions);
app.getExt(`${apiPrefix}/transactions/:transactionIdOrHash`, transactions.getTransactionsByIdOrHash);
```
