### Title
Unbounded Prometheus Label Cardinality via Unmatched Request Paths Enables Memory Exhaustion DoS

### Summary
The `toOpenApiPath` function in `metricsHandler.js` falls back to the raw `req.path` value — fully attacker-controlled — when a request does not match any registered Express route. This unsanitized, unbounded string is stored as the `path` Prometheus label across four per-route instruments. An unprivileged attacker can flood the server with requests to unique, arbitrarily long unmatched paths, causing unbounded growth of the OpenTelemetry metric registry in memory, followed by a massive (potentially gigabyte-scale) serialization payload when `serializer.serialize(resourceMetrics)` is called at the metrics endpoint.

### Finding Description

**Exact code path:**

In `rest/middleware/metricsHandler.js`, `toOpenApiPath` resolves the `path` label:

```
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // set only for matched routes
  if (!path) {
    if (!req.route) {
      path = req.path;                       // ← raw attacker input, no limit
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  ...
};
``` [1](#0-0) 

For any request that does not match a registered route (`req.route` is `null`), `res.locals[requestPathLabel]` is never set (the router middleware only sets it for matched routes): [2](#0-1) 

So `path = req.path` — the raw URL path segment — is used verbatim.

This value is then used as a label on **four** per-route instruments:

```javascript
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
``` [3](#0-2) 

Each unique `(method, path, code)` triple creates a **new time series** in the OpenTelemetry SDK's in-memory registry. For histograms, each unique label set creates multiple data points (one per bucket boundary). With `durationBuckets = [25, 100, 250, 500]` and `responseSizeBuckets = [100, 250, 500, 1000]`, each unique path generates ~12+ stored data points.

When the metrics endpoint is hit, all accumulated time series are serialized synchronously:

```javascript
return exporter.collect().then(({resourceMetrics}) => {
  res.set('Content-Type', 'text/plain; charset=utf-8');
  res.send(serializer.serialize(resourceMetrics));
});
``` [4](#0-3) 

**Root cause:** No length cap, no cardinality limit, and no sanitization is applied to `req.path` before it is stored as a Prometheus label value. The OpenTelemetry SDK has no built-in cardinality protection configured here. [5](#0-4) 

**Why existing checks fail:**

- The `authenticate()` guard only protects the metrics *read* endpoint. The injection vector is ordinary HTTP requests to any path — no authentication required. [6](#0-5) 
- The `requestQueryParser` limits repeated query parameters but applies no constraint to the URL path itself. [7](#0-6) 
- No rate-limiting middleware is present in the server stack between the metrics handler and the route handlers. [8](#0-7) 

### Impact Explanation

Each unique long path sent to an unmatched route is permanently retained in the OpenTelemetry registry for the lifetime of the process. With 100,000 requests each carrying an 8 KB path:

- **Memory**: ~100,000 unique time series × 4 instruments × ~8 KB label string ≈ **3.2 GB** of label data alone, plus histogram bucket storage.
- **Serialization**: `serializer.serialize(resourceMetrics)` is synchronous and single-threaded in Node.js. Serializing millions of time series blocks the event loop, causing all other requests to time out.
- **Cascading failure**: Node.js OOM kill terminates the entire REST API service.

Severity: **High** — complete service unavailability with no recovery until process restart and registry reset.

### Likelihood Explanation

- Requires zero authentication or privileges — any HTTP client can send requests to unmatched paths.
- Node.js default HTTP server accepts URL paths up to ~80 KB; Express does not impose a shorter limit.
- The attack is trivially scriptable with `curl` or any HTTP load tool.
- It is persistent: injected label values survive across scrape cycles and accumulate indefinitely.
- No existing network-layer defense (WAF, rate limiter) is visible in the application code.

### Recommendation

1. **Truncate the path label**: Cap `path` to a safe maximum (e.g., 256 characters) before recording metrics:
   ```javascript
   const MAX_PATH_LABEL_LEN = 256;
   const path = toOpenApiPath(req, res).slice(0, MAX_PATH_LABEL_LEN);
   ```

2. **Normalize unmatched paths**: Replace unmatched paths with a fixed sentinel label such as `"unknown"` or `"unmatched"` instead of using `req.path`:
   ```javascript
   if (!req.route) {
     path = 'unmatched';
   }
   ```

3. **Configure OpenTelemetry cardinality limits**: Use the `cardinalityLimit` option on each instrument to cap the number of unique label sets retained in memory.

4. **Add a rate limiter** (e.g., `express-rate-limit`) early in the middleware stack to limit requests per IP, reducing the attacker's injection throughput.

### Proof of Concept

```bash
# Inject 50,000 unique long paths (each ~4 KB) into the metrics registry
for i in $(seq 1 50000); do
  RAND=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c 4000)
  curl -s "http://target-host/api/v1/${RAND}" > /dev/null &
done
wait

# Trigger serialization — response will be enormous or the server will OOM/hang
curl -v "http://target-host/swagger/metrics/"
```

Each `GET /api/v1/<unique-4KB-string>` returns a 404 (no route match → `req.route` is null → `req.path` is used as label). After the loop, the registry holds ~200,000 time series with 4 KB label values. The final `curl` to the metrics endpoint either returns a multi-gigabyte response, causes the Node.js process to exhaust heap memory, or blocks the event loop long enough to time out all concurrent requests.

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

**File:** rest/middleware/metricsHandler.js (L137-144)
```javascript
const authenticate = (req) => {
  const {authentication, username, password} = config.metrics.config;
  if (!authentication) {
    return true;
  }
  const credentials = basicAuth(req);
  return credentials && tsscmp(credentials.name, username) && tsscmp(credentials.pass, password);
};
```

**File:** rest/middleware/metricsHandler.js (L161-164)
```javascript
      return exporter.collect().then(({resourceMetrics}) => {
        res.set('Content-Type', 'text/plain; charset=utf-8');
        res.send(serializer.serialize(resourceMetrics));
      });
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

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```

**File:** rest/middleware/requestHandler.js (L15-20)
```javascript
const queryOptions = {
  arrayLimit: config.query.maxRepeatedQueryParameters,
  depth: 1,
  strictDepth: true,
  throwOnLimitExceeded: true,
};
```

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
