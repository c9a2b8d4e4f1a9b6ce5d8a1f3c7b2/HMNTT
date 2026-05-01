### Title
Redis Integer-Second TTL Truncation Causes `Cache-Control: public, max-age=0` on Near-Expired Cache Hits

### Summary
`getSingleWithTtl` in `rest/cache.js` uses a Redis `MULTI/EXEC` pipeline (`multi().ttl().get()`) where `TTL` returns integer seconds. When a cached key has less than one second of remaining lifetime, Redis `TTL` returns `0` while `GET` still returns the value (the key has not yet expired). The returned `{ttl: 0, value: ...}` object is then used in `responseCacheCheckHandler` to construct `Cache-Control: public, max-age=0`, instructing clients and intermediate proxies to treat the response as immediately stale, degrading cache efficiency.

### Finding Description
**Code path:**

- `rest/cache.js`, `getSingleWithTtl`, lines 69–79:
  ```js
  const result = await this.redis.multi().ttl(key).get(key).exec()...
  const rawValue = result[1][1];
  if (rawValue) {
    return {ttl: result[0][1], value: JSONParse(rawValue)};
  }
  ```
  Redis `TTL` returns an integer (whole seconds). For a key with 0.1–0.9 seconds remaining, `TTL` returns `0` while `GET` returns the value. The only guard is `if (rawValue)` — there is no check that `ttl > 0`.

- `rest/middleware/responseCacheHandler.js`, `responseCacheCheckHandler`, lines 50 and 58–60:
  ```js
  const {ttl: redisTtl, value: redisValue} = cachedTtlAndValue;
  ...
  const headers = {
    ...cachedResponse.headers,
    ...{[CACHE_CONTROL_HEADER]: `public, max-age=${redisTtl}`},
  };
  ```
  `redisTtl` is used directly in the `Cache-Control` header with no guard for `redisTtl === 0`. When `redisTtl` is `0`, the response is sent with `Cache-Control: public, max-age=0`.

**Root cause:** Redis `TTL` truncates to integer seconds. A key with sub-second remaining lifetime returns `TTL=0` but `GET` still returns the value. Neither `getSingleWithTtl` nor `responseCacheCheckHandler` guards against `ttl === 0`.

**Failed assumption:** The code assumes that if `GET` returns a value, `TTL` will be a positive integer. This is false for keys in their final sub-second of life.

### Impact Explanation
Any client (or shared proxy cache) that receives `Cache-Control: public, max-age=0` will treat the response as immediately stale and will not cache it. This means every subsequent request bypasses the cache, increasing backend load. For shared CDN/proxy deployments, this can affect all downstream consumers of that cached resource simultaneously. The data itself is not corrupted — this is a cache-efficiency griefing issue with no direct economic harm to individual users.

### Likelihood Explanation
An unprivileged attacker can:
1. Make a request to any cacheable endpoint and observe `Cache-Control: max-age=N` in the response.
2. Wait approximately `N - 0.5` seconds (the TTL is public information from the response header).
3. Issue a new request in the final sub-second window.

This is repeatable, requires no credentials, and can be scripted. The window is narrow (sub-second) but predictable given the public `max-age` value. Natural traffic also hits this window without any attacker involvement.

### Recommendation
Add a guard in `getSingleWithTtl` to treat `ttl <= 0` as a cache miss:

```js
const rawValue = result[1][1];
const ttl = result[0][1];
if (rawValue && ttl > 0) {
  return {ttl, value: JSONParse(rawValue)};
}
return undefined;
```

Alternatively, switch from `TTL` (second precision) to `PTTL` (millisecond precision) and convert to seconds with `Math.ceil` before returning, ensuring a minimum of 1 is used in the `Cache-Control` header. This eliminates the sub-second truncation window entirely.

### Proof of Concept
1. Send `GET /api/v1/accounts/0.0.12345/rewards` — observe `Cache-Control: public, max-age=N` (e.g., `max-age=60`).
2. Wait `N - 0.5` seconds (e.g., 59.5 seconds).
3. Send `GET /api/v1/accounts/0.0.12345/rewards` again within the final sub-second window.
4. Observe the response contains valid JSON body but `Cache-Control: public, max-age=0`.
5. Any HTTP client or proxy cache receiving this response will not cache it, forcing a fresh fetch on every subsequent request. [1](#0-0) [2](#0-1)

### Citations

**File:** rest/cache.js (L69-82)
```javascript
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
```

**File:** rest/middleware/responseCacheHandler.js (L50-61)
```javascript
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
```
