### Title
Permanent `inFlightCounter` Inflation via Client-Abort Before Response Flush

### Summary
In `metricsMiddleware()`, `inFlightCounter.add(1)` is called unconditionally on every non-metrics request, but the corresponding `inFlightCounter.add(-1)` lives exclusively inside a `res.on('finish', ...)` handler. In Node.js, the `finish` event is only emitted when the response has been fully written to the OS socket buffer — it is **never** emitted when the client closes the TCP connection before `res.end()` completes. Any unprivileged attacker who sends a valid HTTP request and then immediately resets the connection causes a permanent +1 leak in `api_all_request_in_processing_total` with no recovery path.

### Finding Description
**File:** `rest/middleware/metricsHandler.js`
**Function:** `metricsMiddleware()` (returned by `metricsHandler()`)

```
Line 169:  inFlightCounter.add(1);          // incremented for every request
...
Line 185:  res.on('finish', () => {
Line 186:    inFlightCounter.add(-1);        // ONLY path that decrements
...
Line 211:  });
``` [1](#0-0) [2](#0-1) 

Node.js HTTP semantics (documented in the `http.ServerResponse` API):
- `finish` fires when `res.end()` has been called **and** the data has been handed to the OS buffer.
- `close` fires when the underlying TCP connection is destroyed — including when the client aborts before the server calls `res.end()`.

When a client disconnects mid-flight, only `close` fires; `finish` is never emitted. The code registers no `res.on('close', ...)` handler anywhere in this middleware, so `inFlightCounter.add(-1)` is permanently skipped for every aborted request. [3](#0-2) 

`server.js` applies no connection timeout, no per-IP rate limit, and no connection-count cap before or after the metrics middleware is registered: [4](#0-3) [5](#0-4) 

### Impact Explanation
`api_all_request_in_processing_total` is an `UpDownCounter` (not a gauge reset on scrape). Each leaked `+1` is permanent for the lifetime of the process. After N aborted requests the counter reads N higher than reality. Monitoring/alerting rules that threshold on this metric (e.g., "alert if in-flight > 50") will fire false positives or, conversely, a real spike in legitimate in-flight Hashgraph history queries will be invisible against the inflated baseline. Additionally, `allRequestCounter` (line 195, inside `finish`) is also never incremented for aborted requests, creating a permanent divergence between `api_all_request` and `api_all_request_in_processing_total` that makes both metrics untrustworthy for capacity planning and incident response. [6](#0-5) 

### Likelihood Explanation
No authentication is required to reach any of the instrumented API routes (accounts, transactions, tokens, topics, etc.). The attack requires only the ability to open a TCP connection, send a syntactically valid HTTP/1.1 request line + `Host` header (≈ 40 bytes), and immediately send a TCP RST. This is trivially scriptable with `curl --max-time 0`, `hping3`, or raw sockets. A single attacker with a modest connection rate (e.g., 1 000 req/s) can inflate the counter by millions within minutes. No exploit kit or special knowledge is needed.

### Recommendation
Add a `res.on('close', ...)` handler that decrements the counter only if `finish` has not already fired, using a boolean guard to prevent double-decrement:

```js
let finished = false;

res.on('finish', () => {
  finished = true;
  inFlightCounter.add(-1);
  // ... rest of metrics recording
});

res.on('close', () => {
  if (!finished) {
    inFlightCounter.add(-1);
  }
});
```

Additionally, configure `server.headersTimeout`, `server.requestTimeout`, and a per-IP rate limiter (e.g., `express-rate-limit`) to bound the rate at which new connections can trigger the middleware.

### Proof of Concept

**Preconditions:** Mirror Node REST API is running with `config.metrics.enabled = true` (default). No authentication on API routes.

**Steps:**

```bash
# Step 1 – baseline: scrape the metric
curl -s http://<mirror-node>:<port>/api/v1/metrics | grep api_all_request_in_processing_total
# Expected: api_all_request_in_processing_total 0

# Step 2 – send 1000 requests and abort each immediately after headers are sent
for i in $(seq 1 1000); do
  # --max-time 0.001 causes curl to abort before the server can respond
  curl -s --max-time 0.001 \
    "http://<mirror-node>:<port>/api/v1/transactions" &
done
wait

# Step 3 – re-scrape
curl -s http://<mirror-node>:<port>/api/v1/metrics | grep api_all_request_in_processing_total
# Result: api_all_request_in_processing_total ~1000  (permanently inflated, never decrements)
```

Each iteration increments the counter without a matching decrement, and the value persists until process restart.

### Citations

**File:** rest/middleware/metricsHandler.js (L169-169)
```javascript
    inFlightCounter.add(1);
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

**File:** rest/server.js (L149-166)
```javascript
if (!isTestEnv()) {
  const server = app.listen(port, '0.0.0.0', (err) => {
    if (err) {
      throw err;
    }

    logger.info(`Server running on port: ${port}`);
  });

  // Health check endpoints
  createTerminus(server, {
    healthChecks: {
      '/health/readiness': health.readinessCheck,
      '/health/liveness': health.livenessCheck,
    },
    logger: (msg, err) => logger.error(msg, err),
    onShutdown: health.onShutdown,
  });
```
