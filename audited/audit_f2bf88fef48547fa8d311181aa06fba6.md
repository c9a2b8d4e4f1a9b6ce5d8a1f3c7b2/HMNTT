### Title
Unbounded Prometheus Label Cardinality via Unmatched-Route Path Injection in `toOpenApiPath()`

### Summary
`toOpenApiPath()` in `rest/middleware/metricsHandler.js` falls back to the raw `req.path` value when a request does not match any Express route (`req.route` is `null` and `res.locals[requestPathLabel]` is unset). Because the `res.on('finish')` handler fires for every response including 404s, an unauthenticated attacker can flood the server with requests to arbitrarily distinct paths, causing `requestTotalCounter`, `durationHistogram`, `requestSizeHistogram`, and `responseSizeHistogram` to accumulate an unbounded number of unique label combinations, exhausting the Node.js process memory and degrading or destroying Prometheus metrics collection.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js` lines 13–31 (`toOpenApiPath`) and lines 185–210 (`res.on('finish')` handler):

```
Line 14:  let path = res.locals[requestPathLabel];   // only set for matched routes
Line 17:  if (!req.route) {
Line 18:    path = req.path;                          // RAW user-controlled path
Line 19:  } else { ...normalized route pattern... }
Line 24:  path = path.replace(/:([^/]+)/g, '{$1}');  // only replaces :param tokens
...
Line 192: const labels = {method, path, code};
Line 207: requestTotalCounter.add(1, labels);         // new time-series per unique path
Line 208: durationHistogram.record(duration, labels);
Line 209: requestSizeHistogram.record(..., labels);
Line 210: responseSizeHistogram.record(..., labels);
```

**Root cause and failed assumption:**

`recordRequestPath` (in `rest/routes/index.js` line 19) only sets `res.locals[requestPathLabel]` when a route actually matches. For any request that falls through to the 404 path (`responseHandler` throws `NotFoundError` → `handleError` sends the response), neither `res.locals[requestPathLabel]` nor `req.route` is populated. `toOpenApiPath()` therefore returns the literal `req.path` string. The regex on line 24 only converts Express `:param` tokens to `{param}` — it does nothing to raw path segments like `/1`, `/2`, `/abc123`. The design assumption that "all requests will match a route and receive a normalized path" is violated for every 404.

**Exploit flow:**

1. Attacker sends `GET /api/v1/x1`, `GET /api/v1/x2`, … `GET /api/v1/xN` (no route matches any of these).
2. `metricsMiddleware` runs first, registers `res.on('finish')`.
3. Express finds no matching route; `responseHandler` throws `NotFoundError`; `handleError` sends HTTP 404.
4. `finish` fires; `toOpenApiPath()` returns `/api/v1/x1`, `/api/v1/x2`, … verbatim.
5. Four OpenTelemetry instruments each create a new time-series for every unique `(method, path, code)` triple.
6. After N requests, 4×N new time-series exist in the in-process `MeterProvider` / `PrometheusExporter` state.

**Why existing checks are insufficient:**

- `res.locals[requestPathLabel]` is only written by `recordRequestPath`, which only runs inside matched route handlers — never for 404s. [1](#0-0) 
- The `:param → {param}` regex is purely syntactic and does not normalize arbitrary path segments. [2](#0-1) 
- No rate-limiting middleware is present in the middleware stack (`rest/middleware/index.js` exports no rate-limiter). [3](#0-2) 
- OpenTelemetry's `MeterProvider` has no built-in cardinality cap by default; every distinct attribute set is stored indefinitely.

### Impact Explanation
Each unique path label creates four new in-memory time-series (counter + three histograms, each histogram with multiple bucket entries). Sending 100 000 unique paths creates hundreds of thousands of live time-series objects. This exhausts Node.js heap memory, causing the process to OOM-crash or become unresponsive. Even before OOM, the `/metrics` scrape endpoint must serialize all accumulated time-series on every Prometheus scrape, causing scrape timeouts and loss of all operational visibility — including fee-related and transaction-rate metrics that operators depend on.

### Likelihood Explanation
The attack requires zero authentication, zero API keys, and zero knowledge of the application beyond the fact that it exposes an HTTP API. A single attacker with a basic HTTP client (e.g., `curl` in a loop, `ab`, `wrk`) can generate tens of thousands of unique 404 paths per second. The attack is fully repeatable and can be sustained indefinitely. No existing network-layer protection (WAF, ingress rate-limit) is visible in the codebase itself.

### Recommendation
1. **Normalize unmatched paths to a sentinel label** — in `toOpenApiPath()`, when both `res.locals[requestPathLabel]` and `req.route` are absent, return a fixed string such as `"unknown"` or `"/api/v1/unknown"` instead of `req.path`:
   ```js
   if (!req.route) {
     path = 'unknown';   // was: path = req.path
   }
   ```
2. **Apply an OpenTelemetry cardinality limit** — configure `ViewOptions` with `attributeValueLengthLimit` or use a `View` with an explicit `allowedAttributeValues` list for the `path` label.
3. **Add ingress rate-limiting** — deploy a rate-limiter middleware (e.g., `express-rate-limit`) to bound the request rate per IP before metrics instrumentation runs.

### Proof of Concept
```bash
# Send 50 000 requests to unique unmatched paths (no auth required)
for i in $(seq 1 50000); do
  curl -s "http://<mirror-node-host>/api/v1/nonexistent_path_${i}" &
done
wait

# Scrape metrics — observe thousands of unique api_request_total{path=...} series
curl http://<mirror-node-host>/swagger/metrics/ | grep 'api_request_total' | wc -l
# Expected: ~50 000 distinct lines; process memory near OOM
```

### Citations

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```

**File:** rest/middleware/metricsHandler.js (L24-24)
```javascript
  path = path.replace(/:([^/]+)/g, '{$1}');
```

**File:** rest/middleware/index.js (L1-13)
```javascript
// SPDX-License-Identifier: Apache-2.0

export {authHandler} from './authHandler.js';
export {handleError} from './httpErrorHandler';
export {openApiValidator, serveSwaggerDocs} from './openapiHandler';
export * from './requestHandler';
export {
  cacheKeyGenerator,
  getCache,
  responseCacheCheckHandler,
  responseCacheUpdateHandler,
} from './responseCacheHandler.js';
export {default as responseHandler} from './responseHandler';
```
