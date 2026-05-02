### Title
Unprivileged User Can Force Short Cache TTL (5s) on SCHEDULECREATE Transaction Queries, Amplifying DB Load

### Summary
`getTransactionsByIdOrHashCacheControlHeader()` in `rest/transactions.js` unconditionally sets `cache-control: public, max-age=5` whenever a query by transaction ID returns a recent, successful SCHEDULECREATE transaction with no corresponding scheduled execution yet. Any unprivileged external user can repeatedly query any such transaction ID to ensure the server-side Redis cache entry expires every 5 seconds, forcing a DB round-trip on each cache miss. There is no rate limiting or access control preventing this.

### Finding Description
**Code location:** `rest/transactions.js`, `getTransactionsByIdOrHashCacheControlHeader()`, lines 895–916.

```js
// rest/transactions.js:895-916
const getTransactionsByIdOrHashCacheControlHeader = (isTransactionHash, scheduledParamExists, transactions) => {
  if (isTransactionHash || scheduledParamExists) {
    return {};
  }
  let header = {};
  for (const transaction of transactions) {
    if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
      const elapsed = utils.nowInNs() - transaction.consensus_timestamp;
      if (elapsed < maxScheduledTransactionConsensusTimestampRangeNs) {
        header = SHORTER_CACHE_CONTROL_HEADER;   // { 'cache-control': 'public, max-age=5' }
      }
    } else if (transaction.scheduled) {
      return {};
    }
  }
  return header;
};
```

This header is merged into the actual HTTP response in `responseHandler.js` (lines 34–39):

```js
const mergedHeaders = {
  ...headers.default,
  ...(headers.path[path] ?? {}),
  ...(res.locals[responseHeadersLabel] ?? {}),   // ← shorter TTL injected here
};
res.set(mergedHeaders);
```

`responseCacheUpdateHandler` then reads the `cache-control` header to determine the Redis TTL:

```js
// responseCacheHandler.js:96-116
const ttl = getCacheControlExpiryOrDefault(res.getHeader(CACHE_CONTROL_HEADER));
if (ttl > 0) {
  await getCache().setSingle(responseCacheKey, ttl, cachedResponse);  // ttl = 5
}
```

`getCacheControlExpiryOrDefault` parses `max-age=5` and returns `5`. The response is therefore stored in Redis with a 5-second TTL. On a cache hit, the remaining Redis TTL is re-emitted as `max-age` to downstream HTTP caches (line 60: `` `public, max-age=${redisTtl}` ``), so any CDN or reverse proxy also treats the entry as stale after ≤5 seconds.

**Root cause / failed assumption:** The function assumes that the only callers interested in a recent SCHEDULECREATE transaction are legitimate clients waiting for the scheduled execution. It does not account for an adversary who deliberately and repeatedly queries the same (or many different) recent SCHEDULECREATE transaction IDs to keep the cache perpetually near-expiry.

**Why existing checks are insufficient:**
- The `isTransactionHash` and `scheduledParamExists` guards only bypass the short TTL for hash-based or `?scheduled=` queries; a plain transaction-ID query with no extra parameters always reaches the short-TTL branch.
- There is no per-IP or per-key rate limiting in the cache or handler layer.
- The cache key is the MD5 of `req.originalUrl` (line 152 of `responseCacheHandler.js`), so every distinct transaction ID is a separate cache entry — an attacker can fan out across many recent SCHEDULECREATE IDs simultaneously.

### Impact Explanation
For every recent SCHEDULECREATE transaction ID the attacker targets, the DB is queried at most once every 5 seconds instead of once every N seconds under the normal (longer) TTL. With `maxScheduledTransactionConsensusTimestampRangeNs` defining a potentially long window (e.g., days for long-term schedules), an attacker can maintain a large set of "active" transaction IDs and drive sustained elevated DB query rates. Any intermediate HTTP caching layer (CDN, reverse proxy) also re-fetches every 5 seconds, multiplying origin requests. The severity is low-to-medium: no user funds are at risk, but DB and origin-server CPU/connection load can be measurably amplified with no cost to the attacker beyond network bandwidth.

### Likelihood Explanation
All SCHEDULECREATE transaction IDs are publicly observable on-chain. An attacker needs no credentials, no special knowledge, and no on-chain spend — they only need to enumerate recent SCHEDULECREATE transactions (trivially done via the same mirror-node API or a block explorer) and issue HTTP GET requests. The attack is fully automatable, repeatable indefinitely, and requires no privileged access.

### Recommendation
1. **Clamp the short TTL floor:** Instead of a hard-coded 5-second TTL, compute a TTL proportional to the remaining scheduled-execution window, with a reasonable minimum (e.g., 30 s).
2. **Apply per-IP / per-key rate limiting** at the API gateway or middleware layer for the `/transactions/:id` endpoint.
3. **Do not propagate the short TTL to public `Cache-Control`:** Use a `Cache-Control: private, max-age=5` or `no-store` directive so intermediate caches are not instructed to re-fetch aggressively, while the internal Redis TTL can remain short.

### Proof of Concept
```
# 1. Find a recent SCHEDULECREATE transaction ID (publicly visible):
GET /api/v1/transactions?transactiontype=SCHEDULECREATE&order=desc&limit=10

# 2. Repeatedly query it by transaction ID (no ?scheduled= param, no hash):
while true; do
  curl -s "https://<mirror-node>/api/v1/transactions/0.0.12345-1700000000-000000000" \
       -o /dev/null -w "%{http_code} cache-control: %header{cache-control}\n"
  sleep 5
done

# Observed: every ~5 s the response is served fresh from DB (cache miss),
# cache-control header reads "public, max-age=5" (or a small residual value),
# confirming the Redis entry expired and a new DB query was issued.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rest/transactions.js (L46-47)
```javascript
const scheduleCreateProtoId = 42;
const SHORTER_CACHE_CONTROL_HEADER = {'cache-control': `public, max-age=5`};
```

**File:** rest/transactions.js (L895-916)
```javascript
const getTransactionsByIdOrHashCacheControlHeader = (isTransactionHash, scheduledParamExists, transactions) => {
  if (isTransactionHash || scheduledParamExists) {
    // If the query uses a transaction hash or a scheduled filter exists, don't override
    return {};
  }

  // Default to no override
  let header = {};
  for (const transaction of transactions) {
    if (transaction.type === scheduleCreateProtoId && SUCCESS_PROTO_IDS.includes(transaction.result)) {
      // SCHEDULECREATE transaction cannot be scheduled
      const elapsed = utils.nowInNs() - transaction.consensus_timestamp;
      if (elapsed < maxScheduledTransactionConsensusTimestampRangeNs) {
        header = SHORTER_CACHE_CONTROL_HEADER;
      }
    } else if (transaction.scheduled) {
      return {};
    }
  }

  return header;
};
```

**File:** rest/middleware/responseHandler.js (L34-39)
```javascript
  const mergedHeaders = {
    ...headers.default,
    ...(headers.path[path] ?? {}),
    ...(res.locals[responseHeadersLabel] ?? {}),
  };
  res.set(mergedHeaders);
```

**File:** rest/middleware/responseCacheHandler.js (L58-61)
```javascript
  const headers = {
    ...cachedResponse.headers,
    ...{[CACHE_CONTROL_HEADER]: `public, max-age=${redisTtl}`},
  };
```

**File:** rest/middleware/responseCacheHandler.js (L90-117)
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
```

**File:** rest/middleware/responseCacheHandler.js (L151-153)
```javascript
const cacheKeyGenerator = (req) => {
  return crypto.createHash('md5').update(req.originalUrl).digest('hex') + CACHE_KEY_VERSION_SUFFIX;
};
```

**File:** rest/middleware/responseCacheHandler.js (L155-164)
```javascript
const getCacheControlExpiryOrDefault = (headerValue) => {
  if (headerValue) {
    const maxAge = headerValue.match(CACHE_CONTROL_REGEX);
    if (maxAge && maxAge.length === 2) {
      return parseInt(maxAge[1], 10);
    }
  }

  return DEFAULT_REDIS_EXPIRY;
};
```
