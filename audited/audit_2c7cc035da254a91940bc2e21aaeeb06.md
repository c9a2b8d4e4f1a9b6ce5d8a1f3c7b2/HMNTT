### Title
Synchronous `unzipSync()` on Every Non-Gzip Cache Hit Enables CPU Exhaustion via Crafted `Accept-Encoding`

### Summary
Any unprivileged client can send `Accept-Encoding: identity` (or `Accept-Encoding: *;q=0, gzip;q=0`) to force `negotiate()` to return `false`, causing `cachedResponse.getUncompressedBody()` to call `unzipSync()` synchronously on the Node.js event loop for every cache hit on a compressed cached response. Because the decompressed body is never memoized, this CPU-bound operation is repeated on every such request, allowing an attacker to degrade server performance for all users with no credentials required.

### Finding Description
**Exact code path:**

In `rest/middleware/responseCacheHandler.js` lines 71–72, when a GET request hits a cached entry:

```js
const useCompressed = negotiate(cachedResponse, req, res);
body = useCompressed ? cachedResponse.getBody() : cachedResponse.getUncompressedBody();
```

`negotiate()` (lines 121–135) checks whether the client accepts gzip:

```js
if (cachedResponse.compressed) {
  const negotiator = new Negotiator(req);
  if (negotiator.encoding([GZIP_ENCODING]) === GZIP_ENCODING) {
    // ...
    return true;
  }
}
// falls through → returns false
```

When the client sends `Accept-Encoding: identity`, the `Negotiator` library will not select `gzip`, so `negotiate()` returns `false`. Control falls to `cachedResponse.getUncompressedBody()` in `rest/model/cachedApiResponse.js` line 30:

```js
getUncompressedBody() {
  return this.compressed ? unzipSync(Buffer.from(this.body, 'base64url')) : this.body;
}
```

`unzipSync()` is a **synchronous** zlib call that blocks the Node.js event loop for the full duration of decompression. There is no memoization — the decompressed buffer is not stored anywhere; it is recomputed from scratch on every invocation.

**Root cause / failed assumption:** The design assumes clients will normally accept gzip (the happy path), and the fallback decompression path (`unzipSync`) was not hardened against deliberate, repeated use. The uncompressed body is never cached in memory alongside the compressed form.

### Impact Explanation
Node.js runs on a single-threaded event loop. `unzipSync()` is a blocking call; while it executes, no other I/O or request handling can proceed. An attacker flooding the server with `Accept-Encoding: identity` requests against any popular, large cached endpoint forces repeated synchronous decompression, starving the event loop and degrading or halting response handling for all concurrent users. The larger the cached response body, the greater the per-request CPU cost. This is a server-wide denial-of-service / performance degradation with no authentication required.

### Likelihood Explanation
The attack requires zero privileges — only the ability to send HTTP requests with a standard, RFC-compliant header. `Accept-Encoding: identity` is a valid, commonly used header value. The attack is trivially scriptable (e.g., `ab`, `wrk`, or a simple loop with `curl`), repeatable indefinitely, and requires no knowledge of the application beyond knowing a cacheable endpoint exists. The cache key is based only on URL path+query (line 152), so a single popular endpoint is sufficient to sustain the attack.

### Recommendation
1. **Memoize the decompressed body** inside `CachedApiResponse`: store the uncompressed buffer as a lazy-initialized field so `unzipSync()` is called at most once per cache-deserialization, not once per request.
2. **Prefer async decompression**: replace `unzipSync` with `zlib.gunzip` (async/promisified) so decompression does not block the event loop.
3. **Rate-limit per IP** at the middleware or reverse-proxy layer to bound the request rate from any single client.
4. **Store both forms in cache**: persist the uncompressed body alongside the compressed form in Redis so no runtime decompression is ever needed on the hot path.

### Proof of Concept
**Preconditions:**
- The server has a cached, compressed response for a large endpoint (e.g., `/api/v1/accounts/0.0.12345/rewards` with enough data to exceed `compressThreshold`).

**Steps:**
```bash
# 1. Warm up the cache (normal request)
curl -s -H "Accept-Encoding: gzip" http://mirror-node/api/v1/accounts/0.0.12345/rewards > /dev/null

# 2. Flood with identity-encoding requests (no gzip accepted)
while true; do
  curl -s -H "Accept-Encoding: identity" \
       http://mirror-node/api/v1/accounts/0.0.12345/rewards > /dev/null &
done
```

**Result:** Each request hits the cache, `negotiate()` returns `false`, `unzipSync()` is called synchronously on the event loop for every request. Under sustained load, Node.js event loop lag increases, response latency for all users degrades, and the server may become unresponsive. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/middleware/responseCacheHandler.js (L71-72)
```javascript
    const useCompressed = negotiate(cachedResponse, req, res);
    body = useCompressed ? cachedResponse.getBody() : cachedResponse.getUncompressedBody();
```

**File:** rest/middleware/responseCacheHandler.js (L121-135)
```javascript
const negotiate = (cachedResponse, req, res) => {
  res.setHeader(VARY_HEADER, 'accept-encoding');

  if (cachedResponse.compressed) {
    const negotiator = new Negotiator(req);
    if (negotiator.encoding([GZIP_ENCODING]) === GZIP_ENCODING) {
      res.setHeader(CONTENT_ENCODING_HEADER, GZIP_ENCODING);
      res.setHeader(CONTENT_LENGTH_HEADER, cachedResponse.getLength());
      return true;
    }
  }

  res.setHeader(CONTENT_LENGTH_HEADER, cachedResponse.getUncompressedLength());
  return false;
};
```

**File:** rest/model/cachedApiResponse.js (L29-31)
```javascript
  getUncompressedBody() {
    return this.compressed ? unzipSync(Buffer.from(this.body, 'base64url')) : this.body;
  }
```
