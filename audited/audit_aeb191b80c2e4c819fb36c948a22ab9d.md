### Title
Unbounded Metric Label Cardinality via Unmatched Routes Causes OOM DoS in `metricsMiddleware`

### Summary
The `toOpenApiPath` helper in `rest/middleware/metricsHandler.js` falls back to using `req.path` verbatim as a metric label when no Express route matches a request (`req.route === null`). Because the OpenTelemetry JS SDK allocates a new in-memory accumulator for every unique label combination and there is no rate limiting or cardinality cap, an unauthenticated attacker can exhaust process memory by flooding the server with requests to unique unmatched paths, causing an out-of-memory crash.

### Finding Description

**Exact code path:**

`toOpenApiPath` (lines 13–31) is called inside the `res.on('finish', ...)` handler (lines 185–211) for every HTTP request:

```js
// metricsHandler.js lines 13-31
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // (A) only set for matched sub-routes

  if (!path) {
    if (!req.route) {
      path = req.path;                       // (B) verbatim attacker-controlled path
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  ...
};
``` [1](#0-0) 

Branch **(A)**: `res.locals[requestPathLabel]` is only populated by `recordRequestPath` in `routes/index.js`, which runs only inside the AccountRoutes, BlockRoutes, and ContractRoutes sub-routers — and only when `req.route?.path` is already set (i.e., a route matched). [2](#0-1) 

Branch **(B)**: For any request that does not match a registered Express route, `req.route` is `null` and `res.locals[requestPathLabel]` is unset, so `req.path` — the raw, attacker-supplied URL path — is used verbatim.

That verbatim path is then passed as the `path` label to all four per-route instruments:

```js
// metricsHandler.js lines 192, 207-210
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
``` [3](#0-2) 

The `metricsMiddleware` is registered globally before all routes, so it instruments every request including 404s: [4](#0-3) 

**Root cause / failed assumption:** The code assumes that `req.path` is a bounded, low-cardinality value. In reality, for unmatched routes it is the raw URL path segment, which is fully attacker-controlled and unbounded.

**Why existing checks fail:**
- `responseHandler` throws `NotFoundError` for unmatched routes (line 30), but this only affects the response body — the `res.on('finish', ...)` callback in `metricsMiddleware` still fires after the 404 is sent.
- There is no rate-limiting middleware anywhere in the REST service.
- The OpenTelemetry JS SDK (`@opentelemetry/sdk-metrics`) has no built-in cardinality limit; every unique `{method, path, code}` triple allocates a new accumulator object in the `MeterProvider`'s internal storage. [5](#0-4) 

### Impact Explanation
Each unique path label creates four new in-memory accumulator objects (one per instrument). Sending N unique paths consumes O(N) memory with no upper bound. At sufficient volume (tens of thousands of unique paths), the Node.js process exhausts its heap and crashes with an OOM error, taking down the entire REST API. This is a complete denial-of-service with no data-integrity or confidentiality impact.

### Likelihood Explanation
No authentication or rate limiting is required. Any network-reachable client can send HTTP GET requests. Generating unique paths is trivial (e.g., appending a random UUID or counter to any URL prefix). A single machine with a modest HTTP client library can sustain thousands of requests per second. The attack is repeatable: after a restart the process is immediately vulnerable again. Likelihood is **high**.

### Recommendation
1. **Normalize unmatched-route paths to a sentinel value.** In `toOpenApiPath`, replace the verbatim fallback with a fixed string:
   ```js
   if (!req.route) {
     path = 'unknown';   // or 'unmatched'
   }
   ```
2. **Enforce a cardinality cap** at the OpenTelemetry SDK level using a view with `cardinalityLimit` (available in `@opentelemetry/sdk-metrics` ≥ 1.x):
   ```js
   new MeterProvider({
     readers: [exporter],
     views: [new View({instrumentName: '*', cardinalityLimit: 200})],
   });
   ```
3. **Add rate limiting** (e.g., `express-rate-limit`) as a defense-in-depth measure before the metrics middleware.

### Proof of Concept
```bash
# Send 50,000 requests with unique paths (no auth required)
for i in $(seq 1 50000); do
  curl -s "http://<mirror-node-rest>/api/v1/nonexistent/path-$RANDOM$RANDOM$i" &
done
wait
```

Each request hits `metricsMiddleware`, `req.route` is `null`, `req.path` = `/api/v1/nonexistent/path-<unique>` is used verbatim as the `path` label, and four new OTel accumulators are allocated. After enough iterations the Node.js heap is exhausted and the process crashes with `FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory`.

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

**File:** rest/middleware/metricsHandler.js (L55-105)
```javascript
const initMetrics = () => {
  const {
    durationBuckets = [25, 100, 250, 500],
    requestSizeBuckets = [],
    responseSizeBuckets = [100, 250, 500, 1000],
  } = config.metrics.config;

  exporter = new PrometheusExporter({preventServerStart: true});
  const meterProvider = new MeterProvider({readers: [exporter]});
  const meter = meterProvider.getMeter('mirror-rest');

  // --- Aggregate ingress counters ---
  allRequestCounter = meter.createCounter('api_all_request', {
    description: 'Total number of requests received',
  });
  allSuccessCounter = meter.createCounter('api_all_success', {
    description: 'Total number of successful requests (2xx)',
  });
  allErrorCounter = meter.createCounter('api_all_errors', {
    description: 'Total number of error requests (4xx+5xx)',
  });
  allClientErrorCounter = meter.createCounter('api_all_client_error', {
    description: 'Total number of client error requests (4xx)',
  });
  allServerErrorCounter = meter.createCounter('api_all_server_error', {
    description: 'Total number of server error requests (5xx)',
  });
  // UpDownCounter — name already has _total so no suffix will be added by exporter
  inFlightCounter = meter.createUpDownCounter('api_all_request_in_processing_total', {
    description: 'Number of requests currently being processed',
  });

  // --- Per-route instruments ---
  requestTotalCounter = meter.createCounter('api_request', {
    description: 'Total number of requests per route',
  });
  durationHistogram = meter.createHistogram('api_request_duration_milliseconds', {
    description: 'Request duration in milliseconds',
    unit: 'ms',
    advice: {explicitBucketBoundaries: durationBuckets},
  });
  requestSizeHistogram = meter.createHistogram('api_request_size_bytes', {
    description: 'Request size in bytes',
    unit: 'By',
    advice: {explicitBucketBoundaries: requestSizeBuckets},
  });
  responseSizeHistogram = meter.createHistogram('api_response_size_bytes', {
    description: 'Response size in bytes',
    unit: 'By',
    advice: {explicitBucketBoundaries: responseSizeBuckets},
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

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
