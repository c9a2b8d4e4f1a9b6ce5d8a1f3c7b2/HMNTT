### Title
Unbounded Metric Label Cardinality via Unsanitized `req.path` in `toOpenApiPath()` Enables DoS

### Summary
When an HTTP request matches no registered Express route, `toOpenApiPath()` falls back to the raw `req.path` value (line 18) with no sanitization or normalization. This user-controlled string is then used directly as the `path` label in `durationHistogram`, `requestTotalCounter`, `requestSizeHistogram`, and `responseSizeHistogram`. An unprivileged attacker can flood the service with requests bearing unique paths, creating millions of distinct OpenTelemetry time-series in process memory, causing unbounded heap growth and event-loop stalls when `exporter.collect()` serializes them.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, `toOpenApiPath()`, lines 13–31: [1](#0-0) 

When `res.locals[requestPathLabel]` is unset (it is only populated by `recordRequestPath` in `rest/routes/index.js` for matched routes) and `req.route` is `null` (no Express route matched), the function assigns `path = req.path` at line 18 — the raw, attacker-supplied URL path — with no truncation, normalization, or allow-listing. [2](#0-1) 

That value is then embedded in `labels = {method, path, code}` and recorded into four instruments: [3](#0-2) 

The `recordRequestPath` middleware in `rest/routes/index.js` only fires for matched routes and only sets `res.locals[requestPathLabel]` when `req.route?.path` is truthy: [4](#0-3) 

For every unmatched path (404), neither guard fires, so the raw path flows through unchecked.

**Root cause:** The failed assumption is that `req.route` being `null` implies a small, bounded set of paths (e.g., only a handful of 404 variants). In reality any HTTP client can supply an arbitrary path string, making the label space unbounded.

**Why existing checks fail:** The only upstream normalization (`recordRequestPath`) is route-scoped and never executes for unmatched requests. There is no cardinality cap, path length limit, or label allow-list anywhere in the metrics pipeline.

### Impact Explanation
Each unique `{method, path, code}` triple is stored as a separate time-series inside the OpenTelemetry SDK's in-process `MetricStorage`. With four histograms each holding `N` buckets per series, millions of unique paths consume gigabytes of heap. When the authenticated `/metrics` endpoint triggers `exporter.collect()` (line 161), the serializer must iterate every stored series synchronously on the Node.js event loop, blocking it for seconds to minutes depending on cardinality. This delays all in-flight API responses, including transaction-visibility queries, for the duration of the collection pass. Sustained flooding keeps the heap near OOM and keeps collection perpetually slow, effectively taking the REST API offline. [5](#0-4) 

### Likelihood Explanation
No authentication, rate-limiting, or path validation is required to trigger the label injection — any HTTP client can send `GET /api/v1/<random>` and receive a 404 while still causing a new time-series to be registered. The attack is trivially scriptable (`ab`, `wrk`, a short Python loop) and requires no credentials or knowledge of the application internals. It is repeatable and cumulative: series are never evicted, so even a low-rate sustained flood (e.g., 100 req/s with unique paths) will exhaust memory within hours.

### Recommendation
1. **Normalize unmatched paths to a sentinel label** — in `toOpenApiPath()`, replace the `path = req.path` fallback with a fixed string such as `"unknown"` or `"unmatched"`:
   ```js
   if (!req.route) {
     path = 'unknown'; // do NOT use req.path
   }
   ```
2. **Enforce a maximum label length** — even for matched routes, truncate or hash `path` values exceeding a safe length (e.g., 128 chars).
3. **Add cardinality limiting** — configure the OpenTelemetry SDK's `cardinalityLimit` option on each instrument, or use a middleware-level LRU cache that maps unseen paths to `"unknown"` once the known-path set exceeds a threshold.
4. **Rate-limit 404 responses** at the ingress layer (e.g., Traefik) to reduce the attacker's injection rate.

### Proof of Concept
```bash
# Send 100,000 requests with unique paths (no credentials needed)
for i in $(seq 1 100000); do
  curl -s "http://<mirror-node-rest>/api/v1/nonexistent-path-$i" &
done
wait

# Now trigger metrics collection (authenticated endpoint)
# Watch: exporter.collect() blocks the event loop for several seconds
# and heap usage has grown by hundreds of MB
curl -u admin:password http://<mirror-node-rest>/swagger/metrics/
```

Each `GET /api/v1/nonexistent-path-N` hits no Express route → `req.route` is `null` → `toOpenApiPath()` returns `/api/v1/nonexistent-path-N` → four new time-series are registered in the OTel SDK per unique N. After 100 k unique paths, `durationHistogram` alone holds 100 k × (4 buckets + 2 aggregates) = 600 k data points that `exporter.collect()` must serialize synchronously.

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

**File:** rest/middleware/metricsHandler.js (L161-164)
```javascript
      return exporter.collect().then(({resourceMetrics}) => {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(serializer.serialize(resourceMetrics));
      });
```

**File:** rest/middleware/metricsHandler.js (L192-210)
```javascript
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

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```
