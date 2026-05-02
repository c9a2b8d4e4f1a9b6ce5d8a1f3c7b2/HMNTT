### Title
304 Not Modified Responses Create Unaccounted Metrics Gap in `metricsMiddleware`, Enabling Silent Cache-Based Access to Hashgraph History

### Summary
In `rest/middleware/metricsHandler.js`, the `metricsMiddleware()` function increments `allRequestCounter` for every response but only increments `allSuccessCounter` for 2xx and `allErrorCounter` for 4xx/5xx. HTTP 304 responses fall through all branches unhandled, creating a permanent gap where requests are counted as received but never as successful or erroneous. Any unprivileged user can deliberately trigger 304 responses by sending `If-None-Match` headers matching cached ETags, causing their successful data retrievals to be invisible to both success-rate and error-rate monitoring.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, function `metricsMiddleware()`, lines 194–204:

```js
allRequestCounter.add(1);
if (res.statusCode >= 200 && res.statusCode < 300) {
  allSuccessCounter.add(1);
} else if (res.statusCode >= 400 && res.statusCode < 500) {
  allClientErrorCounter.add(1);
  allErrorCounter.add(1);
} else if (res.statusCode >= 500) {
  allServerErrorCounter.add(1);
  allErrorCounter.add(1);
}
// 3xx (including 304) — no branch, falls through silently
```

**Root cause:** The conditional ladder covers only `[200,300)`, `[400,500)`, and `[500,∞)`. The range `[300,400)` — which includes HTTP 304 — is entirely absent. The failed assumption is that every request will produce either a 2xx, 4xx, or 5xx response.

**304 trigger mechanism** is directly available to any unprivileged caller via `rest/middleware/responseCacheHandler.js`, lines 52–54:

```js
const conditionalHeader = req.get(CONDITIONAL_HEADER); // 'if-none-match'
const clientCached = conditionalHeader && conditionalHeader === cachedResponse.headers[ETAG_HEADER];
const statusCode = clientCached ? httpStatusCodes.UNMODIFIED.code : cachedResponse.statusCode;
```

An attacker needs only to:
1. Make one normal request to any Hashgraph history endpoint (e.g., `GET /api/v1/transactions`) and capture the `ETag` response header.
2. Replay the same request with `If-None-Match: <captured-etag>` — the cache layer returns 304 with the full cached payload body omitted but the data is considered delivered.

Each such 304 response: increments `allRequestCounter` (+1), leaves `allSuccessCounter` unchanged (0), leaves `allErrorCounter` unchanged (0).

**Why existing checks fail:** The `responseCacheCheckHandler` (registered at `server.js` line 97) runs *after* `metricsMiddleware` attaches the `res.on('finish')` listener (line 185), so the metrics listener fires on the 304 response emitted by the cache handler. There is no guard, fallback branch, or catch-all for 3xx in the metrics logic.

### Impact Explanation
- **Success-rate monitoring blind spot:** `allSuccessCounter / allRequestCounter` drops as 304s accumulate, making it appear the API is serving fewer successful responses than it actually is — or, from the attacker's perspective, their successful data retrievals are never counted as successes.
- **Error-rate alert dilution:** `allErrorCounter / allRequestCounter` is diluted by every 304 request. If an alert fires at, e.g., error rate > 5%, an attacker can suppress it by flooding with 304 requests, lowering the ratio below the threshold while simultaneously extracting Hashgraph history data from cache.
- **Aggregate accounting invariant broken:** `allRequestCounter ≠ allSuccessCounter + allErrorCounter + inFlight` at any point in time, making forensic reconstruction of access volume from metrics alone impossible.

Severity: **Medium** — does not grant unauthorized data access on its own, but actively degrades the integrity of the security monitoring layer that is supposed to detect anomalous access patterns.

### Likelihood Explanation
- **No privileges required.** Any HTTP client can send `If-None-Match` headers.
- **Trivially repeatable.** A single cached ETag is valid for the entire Redis TTL window; the attacker can issue thousands of 304-producing requests per second with a one-liner (`curl -H "If-None-Match: <etag>" <endpoint>`).
- **Self-reinforcing.** The more 304 requests sent, the more diluted the error-rate metric becomes, making detection progressively harder.
- **No anomaly in access logs needed.** The requests are individually indistinguishable from normal conditional-GET browser behavior (standard HTTP caching).

### Recommendation
Add an explicit branch for 3xx responses in the aggregate counter logic, treating 304 as a success variant (it represents a valid, fulfilled conditional request):

```js
allRequestCounter.add(1);
if (res.statusCode >= 200 && res.statusCode < 300) {
  allSuccessCounter.add(1);
} else if (res.statusCode >= 300 && res.statusCode < 400) {
  allSuccessCounter.add(1); // 304 is a successful conditional response
} else if (res.statusCode >= 400 && res.statusCode < 500) {
  allClientErrorCounter.add(1);
  allErrorCounter.add(1);
} else if (res.statusCode >= 500) {
  allServerErrorCounter.add(1);
  allErrorCounter.add(1);
}
```

Alternatively, collapse the success branch to `res.statusCode < 400` to cover all non-error responses. Also add a test case in the metrics handler test suite that asserts `allSuccessCounter` is incremented for a 304 response.

### Proof of Concept

```bash
# Step 1: Fetch any Hashgraph history endpoint and capture the ETag
ETAG=$(curl -si https://<mirror-node>/api/v1/transactions?limit=1 \
  | grep -i '^etag:' | awk '{print $2}' | tr -d '\r')

echo "Captured ETag: $ETAG"

# Step 2: Repeatedly send conditional GET requests to trigger 304
for i in $(seq 1 1000); do
  curl -s -o /dev/null -w "%{http_code}\n" \
    -H "If-None-Match: $ETAG" \
    https://<mirror-node>/api/v1/transactions?limit=1
done
# All responses will be 304

# Step 3: Scrape metrics endpoint and observe the gap
curl https://<mirror-node>/swagger/metrics/ | grep -E 'api_all_(request|success|errors)'
# api_all_request_total will be 1000+ higher than api_all_success_total + api_all_errors_total
# Error rate = api_all_errors_total / api_all_request_total is now artificially suppressed
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/middleware/metricsHandler.js (L194-204)
```javascript
      // Aggregate counters
      allRequestCounter.add(1);
      if (res.statusCode >= 200 && res.statusCode < 300) {
        allSuccessCounter.add(1);
      } else if (res.statusCode >= 400 && res.statusCode < 500) {
        allClientErrorCounter.add(1);
        allErrorCounter.add(1);
      } else if (res.statusCode >= 500) {
        allServerErrorCounter.add(1);
        allErrorCounter.add(1);
      }
```

**File:** rest/middleware/responseCacheHandler.js (L52-54)
```javascript
  const conditionalHeader = req.get(CONDITIONAL_HEADER);
  const clientCached = conditionalHeader && conditionalHeader === cachedResponse.headers[ETAG_HEADER]; // 304
  const statusCode = clientCached ? httpStatusCodes.UNMODIFIED.code : cachedResponse.statusCode;
```

**File:** rest/server.js (L89-98)
```javascript
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
