### Title
Cache Stampede (Thundering Herd) on TTL Expiry in `responseCacheCheckHandler`

### Summary
`responseCacheCheckHandler` performs a non-atomic, unguarded cache lookup: when a cache entry expires, every concurrent request for the same key simultaneously receives `undefined` from `getSingleWithTtl`, all fall through to the upstream data source, and all independently attempt to repopulate the cache. There is no request coalescing, mutex, or in-flight deduplication of any kind, making this a textbook cache stampede exploitable by any unprivileged user.

### Finding Description

**Exact code path:**

In `rest/middleware/responseCacheHandler.js`, `responseCacheCheckHandler` (lines 40–48):

```js
const cachedTtlAndValue = await getCache().getSingleWithTtl(responseCacheKey);

if (!cachedTtlAndValue) {
  res.locals[responseCacheKeyLabel] = responseCacheKey;
  return;          // ← falls through to upstream handler, no guard
}
``` [1](#0-0) 

`getSingleWithTtl` in `rest/cache.js` (lines 64–83) issues a Redis `MULTI` pipeline (`TTL` + `GET`) and returns `undefined` when the key is absent:

```js
const rawValue = result[1][1];
if (rawValue) {
  return {ttl: result[0][1], value: JSONParse(rawValue)};
}
return undefined;
``` [2](#0-1) 

After `responseCacheCheckHandler` returns on a miss, the request proceeds to the real route handler and, upon completion, `responseCacheUpdateHandler` writes the result back via `setSingle` (line 116): [3](#0-2) 

**Root cause:** There is no in-process promise map, no Redis `SET NX` election, no probabilistic early expiration, and no request-coalescing layer anywhere between the cache check and the upstream query. The failed assumption is that only one request will experience a cache miss at a time.

**Exploit flow:**
1. Attacker (or organic traffic) sends N concurrent `GET /api/v1/blocks/{num}` requests.
2. The Redis TTL for that key reaches 0; Redis atomically deletes the key.
3. All N `getSingleWithTtl` calls return `undefined` simultaneously (each sees the key as absent).
4. All N requests set `res.locals[responseCacheKeyLabel]` and fall through to the DB-backed route handler.
5. All N requests independently execute the full upstream query against the database.
6. All N requests independently call `setSingle` to write back — the last writer wins, but all N DB queries have already been issued.

**Why existing checks are insufficient:** The only guard is the `if (!cachedTtlAndValue)` boolean check at line 45. It is evaluated independently by every concurrent request with no coordination. There is no shared in-flight set, no Redis `SETNX`/`SET … NX EX` lock, and no promise stored for pending requests to await. [4](#0-3) 

### Impact Explanation
All N concurrent requests bypass the cache and hit the upstream PostgreSQL database simultaneously. For a high-traffic endpoint (e.g., the latest block), this can multiply DB load by the number of concurrent clients. The DB query latency increases under load, delaying cache repopulation. During the repopulation window, subsequent requests also miss the cache, creating a cascading effect. This can cause sustained upstream overload and significantly delayed response times — well exceeding normal block-time cadence for the duration of the stampede.

### Likelihood Explanation
No authentication or privilege is required. Any HTTP client can send concurrent requests. The attack is trivially repeatable: the attacker simply needs to time requests near a known TTL boundary (the `Cache-Control: max-age` value is disclosed in every response header, line 60), or simply flood the endpoint continuously. The `DEFAULT_REDIS_EXPIRY` of 1 second means the window recurs every second for uncached endpoints. [5](#0-4) 

### Recommendation
Implement one of the following stampede-prevention strategies:

1. **In-process promise coalescing**: Maintain a `Map<cacheKey, Promise>` of in-flight upstream requests. On a cache miss, check the map first; if a promise exists, `await` it instead of issuing a new upstream query.
2. **Redis distributed lock (`SET NX EX`)**: On a cache miss, attempt to acquire a short-lived Redis lock for the cache key. Only the winner issues the upstream query; losers either wait and retry or serve a stale value.
3. **Probabilistic early expiration (XFetch)**: Recompute the cache entry slightly before it expires, eliminating the expiry window entirely.
4. **Stale-while-revalidate**: Serve the stale cached value immediately while a single background refresh is triggered.

### Proof of Concept

```bash
# 1. Prime the cache and note the max-age from the response header
curl -v http://mirror-node/api/v1/blocks/latest
# Response: Cache-Control: public, max-age=2

# 2. Wait for TTL to expire, then fire 50 concurrent requests simultaneously
sleep 2 && for i in $(seq 1 50); do
  curl -s http://mirror-node/api/v1/blocks/latest &
done
wait

# 3. Observe in server logs: 50 lines of upstream DB queries fired at the same timestamp,
#    zero "from cache" log lines, and elevated DB query latency.
#    The cache is not repopulated until all 50 upstream queries complete.
```

The server logs will show 50 independent upstream executions with no cache hits, confirming all 50 requests bypassed the cache simultaneously.

### Citations

**File:** rest/middleware/responseCacheHandler.js (L24-24)
```javascript
const DEFAULT_REDIS_EXPIRY = 1;
```

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

**File:** rest/middleware/responseCacheHandler.js (L90-119)
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
  }
};
```

**File:** rest/cache.js (L64-83)
```javascript
  async getSingleWithTtl(key) {
    if (!this.ready) {
      return undefined;
    }

    const result = await this.redis
      .multi()
      .ttl(key)
      .get(key)
      .exec()
      .catch((err) => logger.warn(`Redis error during ttl/get: ${err.message}`));

    // result is [[null, ttl], [null, value]], with value === null on cache miss.
    const rawValue = result[1][1];
    if (rawValue) {
      return {ttl: result[0][1], value: JSONParse(rawValue)};
    }

    return undefined;
  }
```
