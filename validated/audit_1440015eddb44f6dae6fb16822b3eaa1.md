All code references check out. The fallback to `req.path` is confirmed at line 18, `recordRequestPath` only fires for matched routes at line 17-19 of `routes/index.js`, and the raw path flows into all four per-route instruments. The SECURITY.md exclusion for "Impacts that only require DDoS" applies to volumetric flooding — this is an application-level resource exhaustion exploitable with a small number of crafted requests, which is a distinct class of vulnerability.

---

Audit Report

## Title
Unbounded Label Cardinality via User-Controlled Path in `toOpenApiPath()` Metrics Middleware

## Summary
`toOpenApiPath()` in `rest/middleware/metricsHandler.js` falls back to the raw, user-controlled `req.path` for unmatched routes. This value is used directly as the `path` label in four per-route OpenTelemetry instruments, allowing an attacker to create an unbounded number of unique label combinations and cause label cardinality explosion in the OTel SDK.

## Finding Description

In `toOpenApiPath()`, the `path` label is resolved as follows: [1](#0-0) 

When `res.locals[requestPathLabel]` is unset **and** `req.route` is falsy (i.e., no Express route matched), the function falls back to `path = req.path` — the raw URL path from the HTTP request.

`res.locals[requestPathLabel]` is only populated by `recordRequestPath`, which guards on `req.route?.path`: [2](#0-1) 

For any unmatched request, `req.route` is `undefined`, so `recordRequestPath` never sets the label, and `toOpenApiPath()` always takes the raw-path fallback.

This raw path is then used as the `path` label in all four per-route instruments: [3](#0-2) 

The `res.on('finish', ...)` callback fires after `responseHandler` throws `NotFoundError` and sends the 404, so metrics are recorded regardless: [4](#0-3) 

There is no cardinality cap, path normalization, or allowlist applied to the `path` label anywhere in the metrics pipeline.

## Impact Explanation
Each unique `{method, path, code}` triple causes the OTel SDK (`@opentelemetry/sdk-metrics`) to allocate a new internal accumulator and time series for each of the four instruments (`api_request`, `api_request_duration_milliseconds`, `api_request_size_bytes`, `api_response_size_bytes`). With N unique paths and M HTTP methods, the SDK holds 4 × N × M active accumulators in memory. These are never evicted. At scale this causes: unbounded heap growth leading to OOM crashes, CPU exhaustion during metric collection/serialization (the Prometheus scrape endpoint must iterate all time series), and degraded or unavailable observability infrastructure.

## Likelihood Explanation
No authentication, authorization, or rate limiting is required to trigger this. Any external client can send HTTP requests to arbitrary paths. The attack is trivially scriptable — a simple loop generating unique path segments (e.g., UUIDs or sequential integers appended to `/api/v1/`) is sufficient. The attack is persistent: once a label combination is registered in the OTel SDK it is not evicted. A single attacker with a basic HTTP client can execute this attack continuously with low request volume.

## Recommendation
1. **Normalize unmatched paths**: In `toOpenApiPath()`, replace the `req.path` fallback with a static sentinel value such as `"unknown"` or `"/api/v1/unknown"` for all unmatched routes (i.e., when `req.route` is falsy).
2. **Allowlist-based label enforcement**: Before recording any per-route metric, validate that `path` is a member of the statically known set of registered route patterns.
3. **Cardinality cap**: Implement a maximum cardinality limit on the `path` label dimension, dropping or bucketing any label value that exceeds the cap.

## Proof of Concept
```bash
# Send requests to unique paths — each creates a new permanent label combination
for i in $(seq 1 100000); do
  curl -s "http://<mirror-node-host>/api/v1/nonexistent/$i" &
done
wait

# Scrape metrics — response will be enormous and CPU-intensive to generate
curl http://<mirror-node-host>/swagger/metrics/
```

Each request to `/api/v1/nonexistent/<i>` is unmatched, so `req.route` is `undefined`, `recordRequestPath` does not fire, and `toOpenApiPath()` returns the raw path. After 100,000 requests, the OTel SDK holds 400,000 active accumulators (4 instruments × 100,000 paths × 1 method). The Prometheus scrape endpoint must serialize all of them on every scrape interval, causing CPU spikes and eventual OOM.

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

**File:** rest/middleware/metricsHandler.js (L185-211)
```javascript
    res.on('finish', () => {
      inFlightCounter.add(-1);

      const duration = Date.now() - startTime;
      const path = toOpenApiPath(req, res);
      const code = String(res.statusCode);
      const method = req.method;
      const labels = {method, path, code};

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

      // Per-route metrics
      requestTotalCounter.add(1, labels);
      durationHistogram.record(duration, labels);
      requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
      responseSizeHistogram.record(responseSize, labels);
    });
```

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```
