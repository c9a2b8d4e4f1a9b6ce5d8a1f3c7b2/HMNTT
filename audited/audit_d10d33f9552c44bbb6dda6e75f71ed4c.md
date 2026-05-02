### Title
Unbounded HTTP Method Label Cardinality in `metricsMiddleware` Enables Prometheus Metric Pollution

### Summary
In `rest/middleware/metricsHandler.js`, the `metricsMiddleware` function uses `req.method` directly as a Prometheus label value without any normalization or allowlisting. An unprivileged attacker can send requests using non-standard but HTTP-parser-accepted methods (e.g., WebDAV methods: `PROPFIND`, `SEARCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `PROPPATCH`) to create unbounded unique label combinations across `requestTotalCounter`, `durationHistogram`, `requestSizeHistogram`, and `responseSizeHistogram`. No authentication or privilege is required.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, lines 191–192 and 207–210:
```js
const method = req.method;           // raw, unsanitized HTTP method
const labels = {method, path, code};

requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
``` [1](#0-0) [2](#0-1) 

**Root cause:** The failed assumption is that only standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`) will be received. Node.js's `llhttp` HTTP parser accepts a broader set of methods including all WebDAV methods (`PROPFIND`, `PROPPATCH`, `MKCOL`, `COPY`, `MOVE`, `LOCK`, `UNLOCK`, `SEARCH`) and others (`PURGE`, `REPORT`, `REBIND`, `UNBIND`, `ACL`, etc.). All of these reach Express and are reflected verbatim into `req.method`.

**No method normalization exists anywhere in the stack.** The `openApiValidator` middleware is conditionally enabled and even when active has `validateRequests: false` and `ignoreUndocumented: true`, so it does not reject non-standard methods. [3](#0-2) [4](#0-3) 

The `path` label compounds the issue: for unmatched routes, `toOpenApiPath` falls back to the raw `req.path`, making the `{method, path, code}` label space a product of (non-standard methods) × (arbitrary paths) × (status codes). [5](#0-4) 

### Impact Explanation
Each unique `{method, path, code}` triple creates a new time series in the OpenTelemetry SDK's in-memory accumulation store and in the downstream Prometheus scraper. With ~15–20 non-standard methods accepted by `llhttp`, combined with the unbounded `path` label for unmatched routes, an attacker can continuously inflate the cardinality of four histograms and one counter. This causes:
- Unbounded memory growth in the Node.js process (each new label set allocates a new accumulator)
- Prometheus scrape payload bloat, slowing or timing out scrapes
- Corruption of monitoring dashboards and alerting baselines (legitimate method distributions are polluted)

Note: the `PrometheusSerializer` does escape label values (`\`, `"`, `\n`), so truly malformed Prometheus exposition output is not produced for methods accepted by `llhttp`. The impact is cardinality-based resource exhaustion and metric integrity degradation, not serializer corruption. [6](#0-5) 

### Likelihood Explanation
No authentication is required. Any network-reachable client can send a `PROPFIND /api/v1/accounts HTTP/1.1` request. The attack is trivially scriptable: a loop sending requests with rotating non-standard methods and random path suffixes (which fall through to `req.path` as the label) creates a continuously growing label set. The metrics endpoint itself has optional Basic Auth, but the instrumentation path (the `res.on('finish')` handler) runs for every request regardless. [7](#0-6) [8](#0-7) 

### Recommendation
Normalize `req.method` to an allowlist before using it as a label value:

```js
const ALLOWED_METHODS = new Set(['GET','POST','PUT','DELETE','PATCH','HEAD','OPTIONS']);
const method = ALLOWED_METHODS.has(req.method) ? req.method : 'OTHER';
```

Apply the same normalization to the `path` label for unmatched routes (e.g., replace raw `req.path` with a fixed sentinel like `"unknown"` when no route is matched), to prevent the cross-product cardinality explosion.

### Proof of Concept
```bash
# Send non-standard methods to any API endpoint (no auth required)
for METHOD in PROPFIND SEARCH MKCOL COPY MOVE LOCK UNLOCK PROPPATCH PURGE REPORT; do
  curl -s -X $METHOD http://<mirror-node-host>:<port>/api/v1/accounts > /dev/null
done

# Each method creates a new label combination in all four per-route instruments.
# Scrape the metrics endpoint to observe cardinality growth:
curl http://<mirror-node-host>:<port>/swagger/metrics/ | grep api_request_total

# Automate with random paths to maximize cardinality:
for i in $(seq 1 1000); do
  curl -s -X PROPFIND "http://<host>:<port>/api/v1/fake-$RANDOM" > /dev/null
done
# Observe memory growth in nodejs_process_memory_heap_used_bytes metric.
```

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

**File:** rest/middleware/openapiHandler.js (L148-158)
```javascript
const openApiValidator = async (app) => {
  const validateResponses = isTestEnv() ? {allErrors: true} : false;
  const {default: OpenApiValidator} = await import('express-openapi-validator');
  app.use(
    OpenApiValidator.middleware({
      apiSpec: path.resolve(process.cwd(), getSpecPath(1)),
      ignoreUndocumented: true,
      validateRequests: false,
      validateResponses,
    })
  );
```

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
