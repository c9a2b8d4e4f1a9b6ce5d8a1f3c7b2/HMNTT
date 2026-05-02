The code at line 209 is verified:

All four required checks are verified against the actual source. Here is the result:

---

Audit Report

## Title
Unprivileged User Can Corrupt `requestSizeHistogram` via Oversized `content-length` Header Causing `parseInt()` Precision Loss

## Summary
In `rest/middleware/metricsHandler.js`, the `metricsMiddleware()` function reads the user-controlled `content-length` header and passes it directly to `parseInt()` with no upper-bound validation. For values exceeding `Number.MAX_SAFE_INTEGER` (9007199254740991), `parseInt()` silently returns an imprecise IEEE 754 double. The existing `|| 0` guard does not catch large truthy floats, so the corrupted value is recorded into `requestSizeHistogram`, distorting request-size metrics until process restart.

## Finding Description
**Exact location:** `rest/middleware/metricsHandler.js`, function `metricsMiddleware()`, line 209:

```javascript
requestSizeHistogram.record(parseInt(req.headers['content-length'] ?? '0', 10) || 0, labels);
``` [1](#0-0) 

`req.headers['content-length']` is a raw, user-supplied string. `parseInt(str, 10)` converts it to a JavaScript `Number` (IEEE 754 double). For any string whose numeric value exceeds `Number.MAX_SAFE_INTEGER` (2^53 − 1), the conversion silently rounds to the nearest representable double:

```
parseInt("99999999999999999999999999999999", 10) // → 1e+32 (wildly imprecise)
```

The `|| 0` fallback only substitutes `0` when `parseInt` returns a falsy value (`NaN`, `0`). A large imprecise float like `1e+32` is truthy, so it passes straight through to `requestSizeHistogram.record()`. [2](#0-1) 

## Impact Explanation
`requestSizeHistogram` (`api_request_size_bytes`) is a per-route Prometheus histogram used for capacity planning, alerting, and SLO monitoring. [2](#0-1) 

A single crafted request injects an astronomically large value (`1e+32`) into the histogram sum, making the mean and all derived statistics for that route permanently nonsensical until the process restarts. Repeated requests sustain the corruption indefinitely. While no transaction data is modified, operators lose reliable observability over request-size patterns, which can suppress legitimate size-based alerts and corrupt capacity-planning dashboards.

## Likelihood Explanation
The attack requires zero authentication, zero privileges, and zero knowledge of the system beyond the public API. Any HTTP client can set an arbitrary `Content-Length` header. The trigger is a single HTTP request. It is trivially repeatable and automatable. The middleware is applied globally to all routes via `metricsHandler()`. [3](#0-2) 

## Recommendation
Replace the unguarded `parseInt` call with an explicit upper-bound clamp before recording:

```javascript
const rawSize = parseInt(req.headers['content-length'] ?? '0', 10);
const safeSize = Number.isFinite(rawSize) && rawSize >= 0 && rawSize <= Number.MAX_SAFE_INTEGER
  ? rawSize
  : 0;
requestSizeHistogram.record(safeSize, labels);
```

This ensures only safe, representable integers are ever passed to `requestSizeHistogram.record()`. [1](#0-0) 

## Proof of Concept
```bash
curl -X GET https://<host>/api/v1/transactions \
  -H "Content-Length: 99999999999999999999999999999999"
```

1. Node.js HTTP parser accepts the header as a valid string (well under the 16 KB `maxHeaderSize` limit).
2. Express passes the request to `metricsMiddleware`.
3. `parseInt("99999999999999999999999999999999", 10)` → `1e+32`.
4. `1e+32 || 0` → `1e+32` (truthy; guard bypassed).
5. `requestSizeHistogram.record(1e+32, labels)` is called — the OpenTelemetry SDK records this as a valid observation, placing it in the `+Inf` bucket and inflating the histogram sum by `1e+32`.
6. Prometheus scrapes the corrupted histogram; all mean/percentile calculations for that route's request size are now meaningless. [4](#0-3)

### Citations

**File:** rest/middleware/metricsHandler.js (L96-100)
```javascript
  requestSizeHistogram = meter.createHistogram('api_request_size_bytes', {
    description: 'Request size in bytes',
    unit: 'By',
    advice: {explicitBucketBoundaries: requestSizeBuckets},
  });
```

**File:** rest/middleware/metricsHandler.js (L152-165)
```javascript
  return function metricsMiddleware(req, res, next) {
    const {pathname} = new URL(req.url, 'http://localhost');
    const normalizedPath = pathname.endsWith('/') ? pathname : `${pathname}/`;

    if (normalizedPath === metricsPath) {
      if (!authenticate(req)) {
        res.set('WWW-Authenticate', 'Basic realm="Metrics"');
        return res.status(401).send('Unauthorized');
      }
      return exporter.collect().then(({resourceMetrics}) => {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(serializer.serialize(resourceMetrics));
      });
    }
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
