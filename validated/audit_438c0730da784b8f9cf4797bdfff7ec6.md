All referenced code has been verified against the actual repository. Every claim in the finding is accurate.

---

Audit Report

## Title
Metrics Label Injection via Unvalidated `req.path` in `toOpenApiPath()` Enables Prometheus Cardinality Explosion

## Summary
`toOpenApiPath()` in `rest/middleware/metricsHandler.js` falls back to the raw, user-controlled `req.path` when no route matches a request. The only guard — a `startsWith('/api/v1')` prefix check — does not validate the path against any set of known routes. The resulting value is used directly as a `path` label on four Prometheus instruments. An unauthenticated attacker can send arbitrarily many requests with unique path suffixes, each creating new time-series and causing cardinality explosion in Prometheus.

## Finding Description

**Exact code path — `toOpenApiPath()` fallback:** [1](#0-0) 

When `res.locals[requestPathLabel]` is not set (no route handler ran) and `req.route` is `null` (no route matched), the function falls back to `path = req.path` at line 18 — entirely user-controlled. The regex replace at line 24 performs no sanitization. The `startsWith(apiPrefix)` check at line 26 only decides whether to prepend the prefix; it does not validate the path against any allowlist of registered routes.

**`apiPrefix` value confirmed:** [2](#0-1) 

`apiPrefix = '/api/v1'` — any path beginning with that string passes the guard unchanged.

**Labels recorded on four per-route instruments:** [3](#0-2) 

`requestTotalCounter`, `durationHistogram`, `requestSizeHistogram`, and `responseSizeHistogram` all receive the injected `path` label.

**`res.on('finish')` fires for every response, including 404s:** [4](#0-3) 

The callback is unconditional — a 404 response still records the label.

## Impact Explanation
Prometheus stores one time-series per unique label combination. Each unique `path` value injected by an attacker creates new time-series across all four instruments (`api_request_total`, `api_request_duration_milliseconds`, `api_request_size_bytes`, `api_response_size_bytes`). Sending thousands of requests with distinct paths (e.g., `/api/v1/<uuid>`) causes cardinality explosion, exhausting Prometheus heap memory and potentially crashing the scrape target or the Prometheus server itself. This is a denial-of-service against the monitoring plane. Additionally, phantom routes pollute dashboards and alerting rules that rely on the `path` label.

## Likelihood Explanation
No authentication is required to trigger this. The metrics middleware is registered globally for all requests: [5](#0-4) 

Any HTTP client can trigger the `res.on('finish')` callback. The attack is trivially scriptable — a loop sending `GET /api/v1/<uuid>` requests is sufficient. The server returns 404 for each, but the label is still recorded.

## Recommendation
Replace the `req.path` fallback with a fixed sentinel value (e.g., `'unknown'` or `apiPrefix + '/unknown'`) for all unmatched requests. This collapses all 404 traffic into a single time-series instead of one per unique path:

```js
if (!req.route) {
  path = `${apiPrefix}/unknown`; // fixed sentinel — no cardinality growth
} else {
  path = (req.baseUrl ?? '') + req.route?.path;
}
```

Alternatively, maintain an explicit allowlist of known OpenAPI paths and map any unrecognized path to the sentinel before recording the label.

## Proof of Concept
```bash
# Send 10,000 requests with unique paths — each creates new Prometheus time-series
for i in $(seq 1 10000); do
  curl -s "http://<mirror-node>/api/v1/$(uuidgen)" > /dev/null
done
# Prometheus now holds 10,000+ new time-series for api_request_total alone
# (multiplied across method × code × path dimensions)
```

Each request returns HTTP 404, but `res.on('finish')` fires and `toOpenApiPath()` returns the unique path as-is (it starts with `/api/v1`, so the prefix guard passes). The four per-route histograms/counters each record a new label set.

### Citations

**File:** rest/middleware/metricsHandler.js (L13-31)
```javascript
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];

  if (!path) {
    if (!req.route) {
      path = req.path;
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }

  path = path.replace(/:([^/]+)/g, '{$1}');

  if (!path.startsWith(apiPrefix)) {
    return apiPrefix + '/' + path;
  }

  return path;
};
```

**File:** rest/middleware/metricsHandler.js (L185-189)
```javascript
    res.on('finish', () => {
      inFlightCounter.add(-1);

      const duration = Date.now() - startTime;
      const path = toOpenApiPath(req, res);
```

**File:** rest/middleware/metricsHandler.js (L207-210)
```javascript
      requestTotalCounter.add(1, labels);
      durationHistogram.record(duration, labels);
      requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
      responseSizeHistogram.record(responseSize, labels);
```

**File:** rest/constants.js (L19-19)
```javascript
const apiPrefix = '/api/v1';
```

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
