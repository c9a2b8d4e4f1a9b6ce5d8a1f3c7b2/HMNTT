### Title
Missing `close` Event Handler Causes Permanent `inFlightCounter` Leak on Client-Aborted Connections

### Summary
In `metricsMiddleware()`, `inFlightCounter.add(1)` is called unconditionally on every non-metrics request, but the corresponding `inFlightCounter.add(-1)` is placed exclusively inside a `res.on('finish', ...)` handler. In Node.js HTTP, the `finish` event fires only when `res.end()` is called and data is successfully flushed to the kernel buffer. When a client aborts the TCP connection before the server completes its async processing and calls `res.end()`, the underlying socket is destroyed, `finish` never fires, and the counter is never decremented. An unprivileged attacker can repeat this at will, causing `api_all_request_in_processing_total` to drift to arbitrarily large values.

### Finding Description

**Exact code location:** `rest/middleware/metricsHandler.js`, `metricsMiddleware()`, lines 169 and 185–211. [1](#0-0) [2](#0-1) 

**Root cause:** The code assumes that every request that increments `inFlightCounter` will eventually produce a `finish` event. This assumption is false. In Node.js `http.ServerResponse` (which extends `OutgoingMessage`/`Stream`):

- `finish` fires only when `end()` is called **and** the data is successfully written to the socket buffer.
- When a client sends a TCP RST or FIN before the server calls `res.end()`, Node.js destroys the underlying socket. Once the socket is destroyed, any subsequent call to `res.end()` on that response either silently fails or emits an error on the socket — it does **not** emit `finish` on the response stream.
- The `close` event fires on the response when the connection is torn down, but the code registers **no** `res.on('close', ...)` handler.

**Exploit flow:**

1. Attacker opens a TCP connection to the mirror-node REST API.
2. Attacker sends a syntactically valid HTTP GET request (e.g., `GET /api/v1/transactions`).
3. `metricsMiddleware` executes: `inFlightCounter.add(1)` at line 169, then `next()` at line 213.
4. The route handler begins an async database query.
5. Attacker immediately sends a TCP RST (or closes the socket with `socket.destroy()`).
6. Node.js destroys the socket; the response stream's `close` event fires.
7. The route handler eventually resolves and calls `res.end()`, but the socket is already destroyed — `finish` never fires.
8. `inFlightCounter.add(-1)` at line 186 is never reached.
9. The counter is permanently +1 for this request.
10. Repeat from step 1 indefinitely.

**Why existing checks are insufficient:** There are none. The middleware has no `res.on('close', ...)` guard, no `req.on('aborted', ...)` / `req.on('close', ...)` handler, and no periodic reset or sanity-check on `inFlightCounter`. The `UpDownCounter` instrument has no floor. [3](#0-2) 

### Impact Explanation

`api_all_request_in_processing_total` is displayed in the operator Grafana dashboard as "Requests Processing." [4](#0-3) 

An attacker can inflate this gauge to any arbitrary value. Consequences:
- Grafana panels and Prometheus alerts keyed on this metric (e.g., "in-flight > 50 → RED") fire continuously, masking real incidents or causing alert fatigue.
- Operators lose confidence in the metric and may disable alerting, creating a blind spot.
- No economic damage to network users, but operator observability is permanently corrupted until the process is restarted (which resets the in-process counter to 0).

Severity: **Medium** (griefing / observability corruption, no data loss, no privilege escalation).

### Likelihood Explanation

- **Precondition:** None. Any unprivileged client with network access to the REST API port can perform this attack.
- **Tooling:** A simple script using raw TCP sockets or `curl --max-time 0` + `kill -9` suffices. No exploit framework needed.
- **Repeatability:** Fully automatable in a tight loop. A single attacker machine can send thousands of aborted requests per second, inflating the counter by thousands per second.
- **Detection difficulty:** The aborted connections look like ordinary client disconnects in access logs; there is no distinguishing marker.

### Recommendation

Replace the sole `finish` listener with a handler that fires on **either** `finish` or `close`, whichever comes first, using a guard flag to prevent double-decrement:

```js
// rest/middleware/metricsHandler.js — metricsMiddleware()
let decremented = false;
const decrement = () => {
  if (!decremented) {
    decremented = true;
    inFlightCounter.add(-1);
  }
};

res.on('finish', () => {
  decrement();
  // ... rest of metric recording ...
});

res.on('close', decrement);  // fires on aborted connections where finish never fires
```

This ensures that regardless of whether the response completes normally or the connection is torn down mid-flight, the counter is always decremented exactly once.

### Proof of Concept

```bash
# Requires: Node.js, curl, a running mirror-node REST instance on localhost:5551

for i in $(seq 1 500); do
  # Send request and immediately kill curl (simulates TCP abort)
  curl -s --max-time 0.001 http://localhost:5551/api/v1/transactions &
done
wait

# Poll the metrics endpoint — api_all_request_in_processing_total will be
# significantly elevated (close to 500) and will NOT decrease over time.
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total
```

Expected output: `api_all_request_in_processing_total{...} ~500` (and growing with each batch), never returning to 0 without a process restart.

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

**File:** charts/hedera-mirror-common/dashboards/hedera-mirror-rest.json (L253-253)
```json
          "expr": "sum(api_all_request_in_processing_total{container=\"$application\",cluster=~\"$cluster\",namespace=~\"$namespace\",pod=~\"$pod\"})",
```
