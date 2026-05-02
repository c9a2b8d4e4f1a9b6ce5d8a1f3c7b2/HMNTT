### Title
Unbounded Metric Label Cardinality via Unmatched-Route Path Injection in `toOpenApiPath()`

### Summary
`toOpenApiPath()` falls back to the raw `req.path` value for any request that does not match a registered Express route. Because this raw path is used verbatim as the `path` label on all four per-route OpenTelemetry instruments, an unauthenticated attacker can drive unbounded cardinality by sending requests to an unlimited number of unique paths, causing the OTel SDK to allocate a new in-memory time-series entry per unique `{method, path, code}` tuple and exhausting process heap.

### Finding Description

**Exact code path:**

`rest/middleware/metricsHandler.js`, `toOpenApiPath()`, lines 13–31:

```js
const toOpenApiPath = (req, res) => {
  let path = res.locals[requestPathLabel];   // (1)

  if (!path) {
    if (!req.route) {
      path = req.path;                        // (2) ← raw attacker-controlled value
    } else {
      path = (req.baseUrl ?? '') + req.route?.path;
    }
  }
  path = path.replace(/:([^/]+)/g, '{$1}');
  ...
  return path;
};
```

**Root cause — three-way fallback with no sanitisation:**

1. `res.locals[requestPathLabel]` is only populated by `recordRequestPath` in `rest/routes/index.js` (lines 16–21), which guards on `req.route?.path`. For any request that does not match a registered route, this value is never set.
2. `req.route` is `undefined` for unmatched requests (Express only sets it after a handler matches).
3. Therefore branch `(2)` executes and `req.path` — the raw, attacker-supplied URL path — becomes the label value.

**Label use site** (`metricsHandler.js`, lines 189–210):

```js
const path = toOpenApiPath(req, res);
const labels = {method, path, code};

requestTotalCounter.add(1, labels);
durationHistogram.record(duration, labels);
requestSizeHistogram.record(..., labels);
responseSizeHistogram.record(responseSize, labels);
```

Every unique `{method, path, code}` triple causes the `@opentelemetry/sdk-metrics` `MeterProvider` to allocate a new `AttributeHashMap` entry (one per instrument × one per unique label-set). There is no cardinality cap configured anywhere in `initMetrics()`.

**Middleware registration order** (`rest/server.js`, lines 89–92) confirms the metrics middleware wraps every request, including 404s, before any route handler runs:

```js
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler.js');
  app.useExt(metricsHandler());
}
```

### Impact Explanation
Each unique path sent by the attacker creates four new in-memory time-series objects (one per histogram/counter instrument). With the default histogram bucket configuration (`[25, 100, 250, 500]` for duration, `[100, 250, 500, 1000]` for response size), each histogram entry allocates O(buckets) memory. Sending N unique paths consumes O(N) heap. At a sustained rate of thousands of requests per second — trivially achievable with a single `curl` loop or `ab`/`wrk` — the Node.js process heap grows without bound until the OOM killer terminates it, causing a complete denial of service of the mirror-node REST API. No authentication is required; the metrics endpoint itself is protected, but the instrumented path is not.

### Likelihood Explanation
The attack requires no credentials, no special protocol knowledge, and no rate-limit bypass. A single attacker with a script generating sequential unique path segments (e.g., `/api/v1/x0000000001`, `/api/v1/x0000000002`, …) can trigger the condition. The metricsHandler is enabled by default when `config.metrics.enabled` is true. The attack is repeatable across process restarts because the OTel state is re-initialised fresh each time, meaning the attacker can re-exhaust memory after each crash.

### Recommendation
1. **Normalise unmatched paths to a sentinel value** inside `toOpenApiPath()`: when `req.route` is absent and `res.locals[requestPathLabel]` is unset, return a fixed string such as `"unknown"` or `apiPrefix + "/unknown"` instead of `req.path`.
2. **Alternatively, skip per-route label recording for unmatched requests** and only increment the aggregate (no-label) counters.
3. As defence-in-depth, configure an OTel cardinality limit via `MeterProvider` view overrides (`View` with `attributeKeys` allow-list) so that only the known finite set of route templates can appear as label values.

### Proof of Concept

```bash
# Requires: curl, bash. No credentials needed.
# Each iteration sends a request to a unique path → unique OTel label → new heap allocation.

i=0
while true; do
  curl -s "http://<mirror-node-rest>:5551/api/v1/nonexistent_$(printf '%010d' $i)" -o /dev/null
  i=$((i + 1))
done
```

Monitor heap growth:

```bash
# Poll the metrics endpoint (if accessible) for nodejs_process_memory_heap_used_bytes
watch -n1 'curl -s http://<mirror-node-rest>:5551/swagger/metrics/ | grep heap_used'
```

Expected result: `nodejs_process_memory_heap_used_bytes` grows monotonically with each unique path sent, eventually causing an OOM crash of the Node.js process.

**Key lines:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rest/server.js (L89-92)
```javascript
if (config.metrics.enabled) {
  const {metricsHandler} = await import('./middleware/metricsHandler');
  app.useExt(metricsHandler());
}
```
