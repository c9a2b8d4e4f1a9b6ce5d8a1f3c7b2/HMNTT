### Title
Unbounded OpenTelemetry Label Cardinality via User-Controlled Path in `toOpenApiPath`

### Summary
`toOpenApiPath` in `rest/middleware/metricsHandler.js` falls back to the raw, user-supplied `req.path` when a request matches no registered route (`req.route` is `undefined`). This raw path is then used as the `path` label on four per-route OpenTelemetry instruments. Because the OTel SDK stores one in-memory time-series per unique label tuple, an unprivileged attacker can create an unbounded number of unique label sets by sending requests to distinct 404 paths, causing unbounded memory growth.

### Finding Description
**Code path:**

In `rest/middleware/metricsHandler.js` lines 13–31, `toOpenApiPath` resolves the path label in priority order:

1. `res.locals[requestPathLabel]` — set only by `recordRequestPath` in `rest/routes/index.js` for **matched** routes.
2. `(req.baseUrl ?? '') + req.route?.path` — used only when `req.route` is truthy, i.e., a route matched.
3. **Fallback (line 18–19):** `path = req.path` — the raw, attacker-controlled URL path, used whenever no route matched. [1](#0-0) 

For every request, the `res.on('finish', ...)` handler (lines 185–211) calls `toOpenApiPath` and records the result as the `path` label on four instruments: [2](#0-1) 

The `recordRequestPath` middleware in `routes/index.js` only fires for matched routes, so for any 404 request `res.locals[requestPathLabel]` is never populated: [3](#0-2) 

`responseHandler.js` confirms that unmatched routes throw `NotFoundError` (line 30), meaning they always produce a 404 with no `requestPathLabel` set: [4](#0-3) 

**Root cause:** No path length cap, no cardinality limit, and no normalization is applied to `req.path` before it becomes an OTel label. The OTel SDK (`@opentelemetry/sdk-metrics`) stores one in-memory accumulation record per unique attribute set; these records are never evicted between collection cycles for counters and histograms.

**Exploit flow:**
1. Attacker sends `N` HTTP requests, each to a distinct path not registered in Express (e.g., `/api/v1/x1`, `/api/v1/x2`, … or paths with long random segments).
2. Each request finishes with a 404; `toOpenApiPath` returns the raw `req.path`.
3. `requestTotalCounter.add(1, labels)`, `durationHistogram.record(...)`, `requestSizeHistogram.record(...)`, `responseSizeHistogram.record(...)` each create a new accumulation entry keyed on `{method, path, code}`.
4. Memory grows linearly (×4 instruments) with the number of unique paths sent.

**Why existing checks fail:**
- No URL/path length limit is enforced anywhere in `toOpenApiPath` or the surrounding middleware.
- No OTel cardinality cap is configured (`MeterProvider` is created with default settings at lines 62–64).
- No rate limiting is present in this middleware layer. [5](#0-4) 

### Impact Explanation
An attacker can inflate the process's heap by creating arbitrarily many unique OTel time-series entries. Each entry holds label strings plus histogram bucket arrays (4 instruments × N buckets each). With long path strings and high request volume, this can exhaust available heap memory, triggering OOM kills or severe GC pressure, degrading or crashing the REST service for all users. Severity is medium: no data is leaked or corrupted, but service availability is directly threatened.

### Likelihood Explanation
Preconditions: none. Any HTTP client reachable to the public API endpoint can trigger this. The attack is trivially scriptable (a simple loop sending requests to unique paths), requires no authentication, no special knowledge of the system, and is repeatable indefinitely. The only practical barrier is upstream network-level rate limiting, which is not enforced by this codebase.

### Recommendation
1. **Normalize unmatched paths to a fixed sentinel label** (e.g., `"unknown"` or `"/api/v1/unknown"`) instead of using `req.path` when `req.route` is undefined. This eliminates cardinality explosion entirely.
2. **Enforce a maximum path label length** before recording metrics (e.g., truncate to 200 characters).
3. **Configure an OTel cardinality limit** via `MeterProvider` view configuration to cap the number of unique attribute sets per instrument.
4. Optionally, apply request-level rate limiting at the middleware layer for 404 responses.

### Proof of Concept
```bash
# Send 10,000 requests to unique 404 paths
for i in $(seq 1 10000); do
  curl -s "http://<mirror-node-host>/api/v1/nonexistent_path_$i" &
done
wait

# Then scrape metrics and observe unbounded unique 'path' label values:
curl http://<mirror-node-host>/swagger/metrics/
# Output will contain 10,000+ distinct api_request_total{path="..."} lines,
# each consuming memory in the OTel SDK's in-memory store.
```

Each unique path in the loop produces a distinct label tuple stored permanently in the four per-route OTel instruments, with memory growing proportionally to the number of unique paths sent.

### Citations

**File:** rest/middleware/metricsHandler.js (L16-22)
```javascript
  if (!path) {
    if (!req.route) {
      path = req.path;
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
```

**File:** rest/middleware/metricsHandler.js (L62-64)
```javascript
  exporter = new PrometheusExporter({preventServerStart: true});
  const meterProvider = new MeterProvider({readers: [exporter]});
  const meter = meterProvider.getMeter('mirror-rest');
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

**File:** rest/middleware/responseHandler.js (L28-31)
```javascript
  if (responseData === undefined) {
    // unmatched route will have no response data, pass NotFoundError to next middleware
    throw new NotFoundError();
  }
```
