### Title
Unbounded User-Controlled Path Used as Prometheus Label Enables Metric Cardinality Explosion and Memory Exhaustion

### Summary
In `rest/middleware/metricsHandler.js`, the `toOpenApiPath` function falls back to the raw `req.path` value for requests that do not match any registered Express route. This user-controlled string is stored without any length limit or sanitization as a Prometheus label value in the OpenTelemetry SDK's in-memory metric storage. An unprivileged attacker can trigger unbounded cardinality growth by flooding the service with requests to unique non-existent paths, causing memory exhaustion and degrading metric recording for all subsequent requests.

### Finding Description

**Exact code path:**

In `rest/middleware/metricsHandler.js`, `toOpenApiPath` (lines 13–31) resolves the path label as follows:

```js
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // line 14 — only set for matched routes

  if (!path) {
    if (!req.route) {
      path = req.path;                        // line 18 — raw user input, no sanitization
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  path = path.replace(/:([^/]+)/g, '{$1}');  // line 24 — no length check
  ...
};
``` [1](#0-0) 

`res.locals[requestPathLabel]` is only populated by `recordRequestPath` in `rest/routes/index.js` for routes that actually match a registered handler:

```js
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
``` [2](#0-1) 

For any request that does not match a registered route, `req.route` is `undefined` and `res.locals[requestPathLabel]` is never set, so `path = req.path` — the raw, attacker-controlled URL path — is used.

This value is then placed directly into the Prometheus label set and recorded into all four per-route instruments:

```js
const path = toOpenApiPath(req, res);          // line 189
const labels = {method, path, code};           // line 192
requestTotalCounter.add(1, labels);            // line 207
durationHistogram.record(duration, labels);    // line 208
requestSizeHistogram.record(..., labels);      // line 209
responseSizeHistogram.record(..., labels);     // line 210
``` [3](#0-2) 

**Root cause:** The assumption that `req.path` is bounded and low-cardinality is false. For unmatched routes, it is entirely attacker-controlled.

**Why existing checks fail:**

- `recordRequestPath` only fires for matched routes; it provides no protection for 404 paths.
- `server.js` has no rate limiting, no URL length cap, and no middleware that truncates or normalizes unmatched paths before metrics are recorded.
- The OpenTelemetry SDK creates a new in-memory time series for every unique `{method, path, code}` attribute set, with no built-in cardinality limit. [4](#0-3) 

### Impact Explanation

Each unique attacker-supplied path permanently allocates a new time series entry across all four histogram/counter instruments (`api_request`, `api_request_duration_milliseconds`, `api_request_size_bytes`, `api_response_size_bytes`). With no eviction policy in the OpenTelemetry SDK's in-memory store, heap memory grows monotonically. A sustained flood of requests with unique paths (e.g., `/api/v1/x/1`, `/api/v1/x/2`, …, `/api/v1/x/N`) causes:

- **OOM crash** of the Node.js REST service process.
- **Degraded Prometheus scrape performance** as the serializer must iterate over an ever-growing set of time series.
- **Denial of service** for all legitimate API consumers sharing the same process.

Severity: **High** — full service availability impact, no authentication required.

### Likelihood Explanation

The attack requires only the ability to send HTTP GET requests to the public REST API endpoint — no credentials, no special headers, no prior knowledge of the system. The attacker needs only a simple loop sending requests to incrementally different paths. The `metricsMiddleware` is registered unconditionally for all requests when `config.metrics.enabled` is true (the default production configuration). The attack is trivially repeatable and automatable with standard tools (`curl`, `ab`, `wrk`).

### Recommendation

1. **Truncate or cap the path label**: In `toOpenApiPath`, when falling back to `req.path`, truncate to a safe maximum (e.g., 256 characters) and replace the remainder with a sentinel like `…`.
2. **Normalize unmatched paths to a fixed label**: Replace the raw `req.path` fallback with a static string such as `"unknown"` or `"unmatched"` for requests where `req.route` is undefined. This eliminates cardinality entirely for 404 traffic.
3. **Add rate limiting**: Apply a rate-limiting middleware (e.g., `express-rate-limit`) before `metricsMiddleware` to bound the rate at which new label combinations can be created.
4. **Set OpenTelemetry cardinality limits**: Configure `cardinalityLimit` on the `MeterProvider` view to cap the number of unique attribute sets per instrument.

### Proof of Concept

```bash
# Send 50,000 requests to unique non-existent paths (no auth required)
for i in $(seq 1 50000); do
  curl -s "http://<mirror-node-host>/api/v1/nonexistent/path/$i" &
done
wait

# Observe heap growth via the metrics endpoint (if accessible)
curl http://<mirror-node-host>/swagger/metrics/ | grep nodejs_process_memory_heap_used_bytes
```

Each iteration creates a new `{method="GET", path="/api/v1/nonexistent/path/<N>", code="404"}` time series in the OpenTelemetry SDK heap. After sufficient iterations, the Node.js process will exhaust available memory and crash or become unresponsive.

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

**File:** rest/middleware/metricsHandler.js (L185-210)
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

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
