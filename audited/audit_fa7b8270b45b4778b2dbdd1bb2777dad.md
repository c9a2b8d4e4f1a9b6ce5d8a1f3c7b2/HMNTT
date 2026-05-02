### Title
Unbounded Prometheus Label Cardinality via Unmatched URL Paths in `toOpenApiPath()` Leading to REST API Heap Exhaustion

### Summary
`toOpenApiPath()` in `rest/middleware/metricsHandler.js` falls back to the raw `req.path` for any request that does not match a registered Express route (i.e., `req.route === null` and `res.locals[requestPathLabel]` is unset). Because this raw path is used directly as the `path` label on four OpenTelemetry instruments — `durationHistogram`, `requestTotalCounter`, `requestSizeHistogram`, and `responseSizeHistogram` — an unauthenticated attacker can create an unbounded number of unique label combinations by sending requests to never-before-seen URL paths, exhausting the Node.js heap and crashing the REST API process. No application-level rate limiting exists in the REST API to prevent this.

### Finding Description

**Exact code path:**

`toOpenApiPath()` ( [1](#0-0) ) resolves the `path` label in three steps:

1. Check `res.locals[requestPathLabel]` — only set by matched route handlers or `recordRequestPath` middleware ( [2](#0-1) ).
2. If not set and `req.route` is non-null, use the Express route template (`req.baseUrl + req.route.path`), which is bounded.
3. **If not set and `req.route === null` (unmatched route), use `req.path` verbatim** — this is the vulnerable branch ( [3](#0-2) ).

The resulting `path` value is then used as a label on all four per-route instruments: [4](#0-3) 

The `res.on('finish', ...)` callback fires for **every** request, including 404s, because the metrics middleware is registered before any route handler and unconditionally hooks the response finish event: [5](#0-4) 

**Root cause:** The assumption that `req.route` will always be populated for any request that reaches the finish handler is false. Express sets `req.route` only for matched routes; 404 responses leave it null, causing the fallback to the attacker-controlled `req.path`.

**Why existing checks fail:**

- `res.locals[requestPathLabel]` is only set by matched route handlers or `recordRequestPath` — neither fires for unmatched paths.
- The OpenTelemetry SDK (`@opentelemetry/sdk-metrics ^2.6.1`) has no built-in cardinality cap; every unique `{method, path, code}` triple allocates a new in-memory accumulator with histogram bucket arrays.
- A `grep` across all `rest/**/*.js` files finds zero uses of any rate-limiting middleware (`rateLimit`, `throttle`, etc.) in the REST API application code. The rate limiting found in the repository is scoped to the Java `web3` module only. [6](#0-5) 

### Impact Explanation

Each unique path label causes the OpenTelemetry SDK to allocate a new accumulator object containing histogram bucket arrays (4 buckets for duration, 4 for response size, etc.) for each of the four instruments. At tens of thousands of unique paths, heap consumption grows into hundreds of megabytes, triggering aggressive GC pauses that block the Node.js event loop and ultimately an OOM crash of the REST API process. This is a complete denial-of-service of the mirror node REST API — all legitimate API consumers lose access. The block ingestion importer is a separate Java process and is not directly affected, but the REST API serving block/transaction data becomes unavailable.

### Likelihood Explanation

The attack requires no authentication, no special headers, and no knowledge of the system beyond the public API hostname. A single attacker with a basic HTTP client can generate thousands of unique paths (e.g., `GET /api/v1/<uuid>`) in seconds. Each request returns a 404 immediately (low server cost per request), but the label is permanently retained in the in-process metrics store for the lifetime of the process. The attack is trivially repeatable and automatable, and there is no application-level defense to exhaust or bypass.

### Recommendation

1. **Normalize unknown paths to a sentinel label**: In `toOpenApiPath()`, replace the `path = req.path` fallback with a fixed string such as `"unknown"` or `apiPrefix + "/unknown"` so that all unmatched routes collapse to a single label value.
2. **Add a cardinality guard**: Maintain a `Set` of seen label combinations and cap it (e.g., 500 entries); emit a fixed `"cardinality_limit_exceeded"` label once the cap is reached.
3. **Add application-level rate limiting** to the REST API (e.g., `express-rate-limit`) to bound the request rate from any single IP, mitigating this and similar amplification attacks.

### Proof of Concept

```bash
# Send 50,000 requests with unique paths (no auth required)
for i in $(seq 1 50000); do
  curl -s -o /dev/null "https://<mirror-node-rest-host>/api/v1/$(uuidgen)" &
done
wait

# Each request:
# 1. Hits the metricsMiddleware, which hooks res.on('finish')
# 2. Express finds no matching route → req.route = null
# 3. toOpenApiPath() returns req.path verbatim (e.g. "/api/v1/550e8400-...")
# 4. Four OTel instruments each allocate a new accumulator for the unique label
# 5. After ~50k unique paths, heap is exhausted → OOM / event loop stall → REST API crash
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

**File:** rest/routes/index.js (L16-21)
```javascript
const recordRequestPath = async (req, res) => {
  const path = req.route?.path;
  if (path && !path.startsWith(apiPrefix) && !res.locals[requestPathLabel]) {
    res.locals[requestPathLabel] = `${req.baseUrl}${req.route.path}`.replace(/\/+$/g, '');
  }
};
```

**File:** rest/server.js (L57-65)
```javascript
app.disable('x-powered-by');
app.set('trust proxy', true);
app.set('port', port);
app.set('query parser', requestQueryParser);

serveSwaggerDocs(app);
if (openApiValidatorEnabled || isTestEnv()) {
  await openApiValidator(app);
}
```
