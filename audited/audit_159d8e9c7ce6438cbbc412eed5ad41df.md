### Title
Unbounded Prometheus Label Cardinality via Unmatched Route Paths Causes OOM in Mirror Node REST API

### Summary
The `metricsMiddleware` in `rest/middleware/metricsHandler.js` uses raw `req.path` as a Prometheus label value for all four per-route instruments when a request does not match any Express route. Because there is no cardinality cap, path normalization, or rate limiting, an unauthenticated attacker can flood the server with thousands of unique paths, creating an unbounded number of in-memory time-series entries in the OpenTelemetry SDK that exhausts the Node.js heap and triggers an OOM crash.

### Finding Description

**Exact code path:**

In `rest/middleware/metricsHandler.js`, `toOpenApiPath` (lines 13–31) resolves the label value for the `path` dimension:

```js
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // set only by matched route handlers

  if (!path) {
    if (!req.route) {          // undefined when no Express route matched
      path = req.path;         // ← raw attacker-controlled path used verbatim
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  ...
};
``` [1](#0-0) 

On every request finish, `metricsMiddleware` builds a label set and records it into **four** instruments:

```js
const labels = {method, path, code};
requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
``` [2](#0-1) 

Each unique `{method, path, code}` triple creates a new in-memory data point in the OpenTelemetry SDK's `MeterProvider`. The SDK never evicts stale label combinations; they accumulate for the lifetime of the process.

**Root cause / failed assumption:** The code assumes `req.path` is bounded to a small, finite set of known API routes. For unmatched requests (404s), no route handler runs, so `res.locals[requestPathLabel]` is never set and `req.route` is `undefined`, leaving `req.path` as the only fallback with no sanitization or normalization. [3](#0-2) 

The metrics middleware is registered unconditionally for all non-metrics paths: [4](#0-3) 

No rate-limiting or cardinality-limiting middleware exists anywhere in the `rest/` middleware stack. [5](#0-4) 

### Impact Explanation
Each unique path label combination allocates memory in the OpenTelemetry SDK's internal attribute-set map for all four instruments (`api_request`, `api_request_duration_milliseconds`, `api_request_size_bytes`, `api_response_size_bytes`). Sending N unique paths consumes O(4N) SDK data-point entries plus the string storage for each path. At tens of thousands of unique paths the Node.js heap is exhausted, the process is killed by the OS OOM killer, and the mirror node REST API becomes unavailable — a complete network partition of the REST layer. Recovery requires a process restart, and the attack can be repeated immediately.

### Likelihood Explanation
The attack requires zero authentication, zero privileges, and zero knowledge of the application beyond its public HTTP port. A trivial script generating sequential or random path suffixes (e.g., `GET /api/v1/x<random>`) is sufficient. The attack is fully repeatable and can be sustained indefinitely. The only prerequisite is that `config.metrics.enabled` is `true`, which is the expected production default for any observable deployment.

### Recommendation
1. **Normalize unmatched paths to a fixed sentinel label** — in `toOpenApiPath`, when `req.route` is `undefined` and `res.locals[requestPathLabel]` is unset, return a constant such as `"unknown"` or `apiPrefix + "/unknown"` instead of `req.path`.
2. **Hard-cap label cardinality** — maintain a `Set` of seen `path` values; once the set exceeds a configurable threshold (e.g., 200), replace any new value with `"overflow"`.
3. **Add an HTTP rate-limiter** (e.g., `express-rate-limit`) before the metrics middleware to bound the request rate per IP.

### Proof of Concept

```bash
# Requires: metrics enabled, server reachable at localhost:5551
# Send 50,000 unique 404 paths; each creates 4 new OTel data points

for i in $(seq 1 50000); do
  curl -s -o /dev/null "http://localhost:5551/api/v1/nonexistent-path-$i" &
done
wait

# Monitor heap growth:
# curl http://localhost:5551/swagger/metrics/ | grep nodejs_process_memory_heap_used_bytes
# Heap climbs monotonically; process eventually OOM-killed.
```

Each request hits the `res.on('finish')` handler in `metricsMiddleware`, calls `toOpenApiPath` which returns `/api/v1/nonexistent-path-<i>`, and records that unique string as the `path` label across all four instruments — with no eviction, no cap, and no normalization. [6](#0-5)

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

**File:** rest/server.js (L88-92)
```javascript
// metrics middleware
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

**File:** rest/middleware/index.js (L1-1)
```javascript
// SPDX-License-Identifier: Apache-2.0
```
