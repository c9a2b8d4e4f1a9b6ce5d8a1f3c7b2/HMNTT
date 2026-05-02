The code is confirmed. Let me verify the exact line numbers and cross-check the SECURITY.md exclusions before rendering a verdict.

**Code verification (confirmed):**

- [1](#0-0)  — `inFlightCounter.add(1)` unconditionally on every non-metrics request.
- [2](#0-1)  — sole decrement path is inside `res.on('finish', ...)`.
- No `res.on('close', ...)` handler exists anywhere in the file. [3](#0-2) 
- `inFlightCounter` is an `UpDownCounter`. [4](#0-3) 

**SECURITY.md scope check:**

The exclusion "Impacts that only require DDoS" does not apply here. This is a **logic bug causing permanent state corruption**: a single aborted connection produces a permanent +1 leak that never self-corrects. That is categorically different from a transient DoS. No other exclusion in the SECURITY.md covers this. [5](#0-4) 

---

Audit Report

## Title
`inFlightCounter` Permanent Leak via Missing `res.on('close')` on Aborted TCP Connections

## Summary
`metricsMiddleware()` in `rest/middleware/metricsHandler.js` increments `inFlightCounter` for every incoming non-metrics request but only decrements it inside a `res.on('finish', ...)` handler. Node.js never fires `finish` when a client aborts the TCP connection before the response is written; it fires `close` instead. Because no `close` listener is registered, the decrement is permanently skipped, causing `api_all_request_in_processing_total` to grow without bound until the process is restarted.

## Finding Description
**File:** `rest/middleware/metricsHandler.js`, function `metricsMiddleware()`

- **Line 169** — `inFlightCounter.add(1)` is called unconditionally for every request that is not the metrics endpoint.
- **Lines 185–186** — `res.on('finish', () => { inFlightCounter.add(-1); ... })` is the **only** decrement path.

In Node.js `http.ServerResponse` (a `stream.Writable`):
- `finish` fires after `res.end()` has been called and all data has been flushed to the OS buffer.
- `close` fires when the underlying TCP socket is destroyed — including when the client sends RST/FIN before the server writes any response.

When a client aborts mid-flight (e.g., while the server awaits a database query), `res.end()` is never called, `finish` never fires, and the counter is permanently off by +1 for that request. There is no secondary decrement path, no timeout-based cleanup, and no periodic reset anywhere in `metricsHandler.js`. The `httpErrorHandler.js` error middleware calls `res.status(...).json(...)` only for requests that reach it — aborted connections that drop before any response bypass it entirely.

## Impact Explanation
`api_all_request_in_processing_total` is an `UpDownCounter` scraped by Prometheus. Each aborted connection permanently inflates the gauge by 1 until process restart. An attacker sending N such requests causes the gauge to read N higher than reality indefinitely. This:
- Corrupts the "Requests Processing" panel in the operator Grafana dashboard.
- Can trigger false high-watermark alerts (documented threshold: 50).
- Masks real overload conditions, degrading operator observability with no self-correcting mechanism.

## Likelihood Explanation
No authentication or rate limiting is required. Any unprivileged user with network access to the REST API port can:
1. Open a TCP connection and send a valid HTTP request line + headers.
2. Immediately close the socket with `SO_LINGER = 0` (sends TCP RST) before the server responds.
3. Repeat.

This is trivially scriptable with `curl --max-time 0`, raw sockets, or `ab`. The only precondition is that the server takes non-zero time to respond (any DB-backed endpoint qualifies). The attack is stateless, repeatable, and leaves no server-side log evidence beyond normal connection-close events.

## Recommendation
Register a `close` listener alongside the existing `finish` listener, using a flag to ensure the decrement executes exactly once regardless of which event fires first:

```js
res.on('finish', onDone);
res.on('close',  onDone);

let done = false;
function onDone() {
  if (done) return;
  done = true;
  inFlightCounter.add(-1);
  // ... rest of metrics recording
}
```

This is the standard Node.js pattern for reliably tracking in-flight requests through both normal completion and client-abort paths.

## Proof of Concept
```bash
# Start a DB-backed request and abort immediately (Linux/macOS)
# The server is still awaiting the DB query when the socket is closed.
curl --max-time 0.001 http://<host>/api/v1/transactions 2>/dev/null || true

# Repeat 60 times
for i in $(seq 1 60); do
  curl --max-time 0.001 http://<host>/api/v1/transactions 2>/dev/null || true
done

# Scrape metrics — api_all_request_in_processing_total will read ~60
# even though zero requests are actually in flight.
curl http://<host>/api/v1/metrics/ | grep api_all_request_in_processing_total
```
Expected output: `api_all_request_in_processing_total 60` (or higher), persisting indefinitely across subsequent legitimate requests.

### Citations

**File:** rest/middleware/metricsHandler.js (L83-85)
```javascript
  inFlightCounter = meter.createUpDownCounter('api_all_request_in_processing_total', {
    description: 'Number of requests currently being processed',
  });
```

**File:** rest/middleware/metricsHandler.js (L152-214)
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

    // Instrument all other requests
    const startTime = Date.now();
    inFlightCounter.add(1);

    // Intercept response writes to measure actual body size
    let responseSize = 0;
    const originalWrite = res.write.bind(res);
    const originalEnd = res.end.bind(res);

    res.write = function (chunk, ...args) {
      responseSize += getChunkSize(chunk);
      return originalWrite(chunk, ...args);
    };
    res.end = function (chunk, ...args) {
      responseSize += getChunkSize(chunk);
      return originalEnd(chunk, ...args);
    };

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

    next();
  };
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
