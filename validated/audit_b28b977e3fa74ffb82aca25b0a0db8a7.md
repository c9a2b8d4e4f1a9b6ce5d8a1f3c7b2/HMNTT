All referenced code is confirmed in the actual repository. Every claim in the report maps precisely to the real code. Here is the audit:

---

Audit Report

## Title
Metrics Cardinality Explosion via Unbounded `path` Label on Unmatched Routes (DoS)

## Summary
The `metricsMiddleware` in `rest/middleware/metricsHandler.js` uses the raw, attacker-controlled `req.path` as a Prometheus label for requests that do not match any registered Express route. Because there is no cardinality cap or path normalization for unmatched routes, an unprivileged attacker can create an unbounded number of unique time series in the `MeterProvider`'s in-memory accumulation map, exhausting Node.js heap memory and crashing the REST API.

## Finding Description

**Middleware registration order** — `metricsHandler()` is registered globally before all route handlers: [1](#0-0) 

This means the `res.on('finish', ...)` callback is attached to **every** request unconditionally, including those that match no route.

**Unmatched-route branch in `toOpenApiPath`** — when a request matches no route, both `res.locals[requestPathLabel]` (never set for unmatched routes) and `req.route` (undefined) are falsy, so the function falls through to `path = req.path`: [2](#0-1) 

**`recordRequestPath` only runs inside matched sub-routers** — it is wired only to `AccountRoutes`, `BlockRoutes`, and `ContractRoutes` routers, so `res.locals[requestPathLabel]` is never populated for unmatched routes: [3](#0-2) 

**Label recording on `finish`** — the raw path is used as a label across four instruments, creating four new time series per unique path: [4](#0-3) 

**Why `responseHandler.js` does not help** — it throws `NotFoundError` for unmatched routes, but this only affects the HTTP response body/status. The `finish` event fires after the response is sent, so the metrics callback still executes with the raw path: [5](#0-4) 

There is no rate-limiting, path-length cap, cardinality guard, or normalization of unmatched paths anywhere in the metrics pipeline.

## Impact Explanation
Each unique path sent by an attacker creates four new heap-allocated time series (one per counter/histogram instrument). With sustained flooding of unique paths (e.g., `GET /api/v1/<uuid>`), heap memory grows monotonically. When the Node.js heap limit is reached, the process crashes with an OOM error, taking down the REST API entirely. This is a memory-exhaustion DoS caused by a specific code defect, not a volumetric network flood.

## Likelihood Explanation
The attack requires only the ability to send HTTP requests to the public REST API (port 5551 by default). No credentials or special protocol knowledge are needed. A trivial loop generating random path suffixes is sufficient. The metrics endpoint is enabled by default (`hiero.mirror.rest.metrics.enabled: true`). The attack is repeatable and sustainable indefinitely.

## Recommendation
In `toOpenApiPath`, replace the raw `req.path` fallback for unmatched routes with a fixed sentinel label (e.g., `"unknown"` or `"unmatched"`):

```js
if (!req.route) {
  path = 'unknown'; // was: path = req.path
}
```

This bounds cardinality for unmatched routes to a single time series per `{method, code}` combination regardless of how many unique paths are sent.

## Proof of Concept
```bash
# Flood the server with unique unmatched paths
for i in $(seq 1 100000); do
  curl -s "http://localhost:5551/api/v1/$(uuidgen)" &
done
wait
```

Each request hits the unmatched-route branch in `toOpenApiPath`, assigns `path = req.path` (a unique UUID path), and records four new time series. After sufficient iterations, the Node.js process exhausts heap memory and crashes.

### Citations

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```

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

**File:** rest/routes/index.js (L16-23)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};

[AccountRoutes, BlockRoutes, ContractRoutes].forEach(({router}) => router.useExt(recordRequestPath));
```

**File:** rest/middleware/responseHandler.js (L26-31)
```javascript
const responseHandler = async (req, res, next) => {
  const responseData = res.locals[responseDataLabel];
  if (responseData === undefined) {
    // unmatched route will have no response data, pass NotFoundError to next middleware
    throw new NotFoundError();
  }
```
