### Title
Unbounded Metric Label Cardinality via User-Controlled Path in `metricsMiddleware`

### Summary
The `metricsMiddleware` in `rest/middleware/metricsHandler.js` records per-route metrics using a `path` label derived from `req.path` when no route matches. Because `req.path` is fully attacker-controlled and no cardinality limit or path sanitization exists, an unprivileged attacker can flood the server with requests carrying unique URL paths, creating an unbounded number of distinct label sets in the OpenTelemetry SDK's in-memory aggregation maps, leading to heap memory exhaustion.

### Finding Description

**Exact code path:**

`toOpenApiPath()` (lines 13–31, `rest/middleware/metricsHandler.js`) resolves the metric path label as follows:

```javascript
if (!path) {
  if (!req.route) {
    path = req.path;          // ← raw attacker-controlled value
  } else {
    path = (req.baseUrl ?? '') + req.route?.path;
  }
}
// ...
if (!path.startsWith(apiPrefix)) {
  return apiPrefix + '/' + path;  // ← prepends prefix, still unique per request
}
```

When no route matches (`req.route === null`), `path` is set to `req.path` verbatim. If the path does not start with `apiPrefix` (`/api/v1`), the function prepends `apiPrefix + '/'`, but the result is still unique per request.

`metricsMiddleware` (lines 185–211) then uses this value as the `path` dimension in four per-route instruments:

```javascript
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
```

The middleware is registered globally at `rest/server.js` line 91 (`app.useExt(metricsHandler())`), before all route handlers, so it intercepts every request including those that result in 404s.

**Root cause:** The OpenTelemetry SDK stores one aggregation entry per unique label set. With no cardinality cap and no path normalization, each unique `{method, path, code}` triple allocates a new in-memory entry (plus per-bucket arrays for each histogram). There is no rate limiting, no allowlist check, and no cardinality guard anywhere in the middleware stack for the REST service.

**Failed assumption:** The code assumes `req.path` will only take on a bounded set of values (the defined API routes). This assumption fails for unmatched paths, which are fully attacker-controlled.

### Impact Explanation
Each unique path sent by the attacker creates four new aggregation entries (one counter + three histograms), each with bucket arrays. With `durationBuckets = [25, 100, 250, 500]` (4 boundaries → 6 buckets) and `responseSizeBuckets = [100, 250, 500, 1000]` (4 boundaries → 6 buckets), each unique path allocates ~12+ bucket slots plus map overhead. Sending tens of thousands of unique paths (trivially achievable with a simple script) causes the Node.js heap to grow without bound, eventually triggering OOM or severe GC pressure, degrading or crashing the service. The >30% heap increase threshold is reachable with a modest sustained flood.

### Likelihood Explanation
No authentication is required to send HTTP requests to the REST API. The attack requires only a basic HTTP client capable of generating requests with unique URL paths (e.g., appending a counter or random string). It is repeatable, requires no special knowledge, and is not blocked by any middleware in the current stack. The Rosetta service has rate limiting in its Helm chart, but the REST API (`rest/server.js`) has no equivalent protection.

### Recommendation
1. **Normalize unknown paths to a fixed sentinel label** (e.g., `"unknown"` or `apiPrefix + "/unknown"`) when `req.route` is null, instead of using `req.path` raw.
2. **Implement a cardinality cap** in the metrics recording logic: maintain a set of seen `path` label values and reject (or map to a sentinel) any value beyond a configured maximum (e.g., 200 distinct paths).
3. **Add an ingress-level rate limiter** (e.g., `express-rate-limit`) to the REST API server, mirroring the rate limiting already present in the Rosetta Helm chart.

### Proof of Concept

```bash
# Send 50,000 requests with unique paths (no auth required)
for i in $(seq 1 50000); do
  curl -s "http://<mirror-node-rest>:5551/attack-path-$i" &
done
wait

# Observe heap growth via the metrics endpoint itself:
curl http://<mirror-node-rest>:5551/swagger/metrics/ | grep nodejs_process_memory_heap_used_bytes
```

Each request with path `/attack-path-$i` causes `toOpenApiPath` to return `/api/v1//attack-path-$i` (a unique value), which is stored as a new label set in all four per-route instruments. After 50 000 unique paths, the heap will have grown by hundreds of MB compared to baseline, well exceeding the 30% threshold for a typical deployment.

**Relevant code locations:**
- `toOpenApiPath`, lines 16–28: [1](#0-0) 
- Per-route metric recording with user-derived label, lines 189–210: [2](#0-1) 
- Global middleware registration (no rate limiting before it), lines 88–92: [3](#0-2)

### Citations

**File:** rest/middleware/metricsHandler.js (L16-28)
```javascript
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
```

**File:** rest/middleware/metricsHandler.js (L189-210)
```javascript
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
```

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
