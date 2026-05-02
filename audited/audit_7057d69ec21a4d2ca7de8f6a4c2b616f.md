### Title
`inFlightCounter` Permanent Leak via Missing `res.on('close')` on Aborted TCP Connections

### Summary
In `metricsMiddleware()`, `inFlightCounter.add(1)` is called unconditionally for every incoming request, but `inFlightCounter.add(-1)` is placed exclusively inside a `res.on('finish', ...)` handler. In Node.js HTTP, the `finish` event fires only when the response has been fully written to the underlying socket. When a client aborts the TCP connection before the server sends a response, Node.js emits `close` on the response object but never `finish`, so the decrement never executes. Any unprivileged external user can exploit this to make `api_all_request_in_processing_total` grow without bound.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, function `metricsMiddleware()`:

- Line 169: `inFlightCounter.add(1)` — unconditionally incremented for every non-metrics request.
- Lines 185–186: `res.on('finish', () => { inFlightCounter.add(-1); ... })` — the **only** decrement path.

There is no `res.on('close', ...)` handler anywhere in the middleware.

**Root cause / failed assumption:**

The code assumes that every request that increments the counter will eventually cause `res` to emit `finish`. This assumption is false. In Node.js `http.ServerResponse` (which inherits from `stream.Writable`):

- `finish` fires when `res.end()` has been called **and** all data has been flushed to the OS buffer.
- `close` fires when the underlying TCP socket is destroyed — including when the client sends a RST or FIN before the server has written the response.

If the client aborts the connection while the server is still processing (e.g., waiting on a database query), `res.end()` is never called (or, if called on a destroyed socket, the stream may not reach the `finish` state). Node.js emits `close` on `res`, but since no `close` listener is registered, the decrement at line 186 is never reached. The counter is permanently off by +1 for each such aborted request.

**Why existing checks are insufficient:**

There are no other decrement paths, no timeout-based cleanup, no periodic reset, and no `close` event listener anywhere in `metricsHandler.js`. The `httpErrorHandler.js` error middleware calls `res.status(...).json(...)` which calls `res.end()`, but only for requests that reach the error handler — aborted connections that drop mid-flight before any response is written bypass this entirely.

### Impact Explanation
`api_all_request_in_processing_total` is an `UpDownCounter` (line 83) scraped by Prometheus and displayed in the operator Grafana dashboard (threshold alert at value 50). An attacker sending N abort-on-connect requests causes the gauge to read N higher than reality, permanently (until process restart). This corrupts the "Requests Processing" panel, can trigger false high-watermark alerts, and masks real overload conditions — degrading operator observability with no way to self-correct short of restarting the process.

### Likelihood Explanation
No authentication or rate limiting is required. Any unprivileged user with network access to the REST API port can:
- Open a TCP connection, send a valid HTTP GET request line + headers, then immediately send a TCP RST (or simply close the socket with `SO_LINGER = 0`).
- Repeat in a tight loop.

This is trivially scriptable with standard tools (`curl`, `ab`, raw sockets). The attack is repeatable, stateless, and leaves no server-side log evidence beyond normal connection-close events. The only precondition is that the server is processing a request that takes non-zero time (any DB-backed endpoint qualifies).

### Recommendation
Register a `close` event listener alongside `finish`, using a one-shot flag to prevent double-decrement (since `close` can fire after `finish` on normal completions):

```js
// rest/middleware/metricsHandler.js  ~line 185
let settled = false;
const onSettle = () => {
  if (settled) return;
  settled = true;
  inFlightCounter.add(-1);
  // ... move all other finish-handler logic here ...
};

res.on('finish', onSettle);
res.on('close',  onSettle);   // fires on client abort before finish
```

This is the pattern used by `express-prom-bundle`, `prom-client`'s `collectDefaultMetrics`, and the Node.js documentation for in-flight request tracking.

### Proof of Concept
```bash
# 1. Start the mirror-node REST service with metrics enabled.

# 2. Baseline — record current counter value:
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total

# 3. Send 100 requests that abort immediately after the TCP handshake
#    (SO_LINGER=0 forces RST before the server writes a response):
python3 - <<'EOF'
import socket, time
for _ in range(100):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                 __import__('struct').pack('ii', 1, 0))  # RST on close
    s.connect(('127.0.0.1', 5551))
    s.send(b'GET /api/v1/transactions HTTP/1.1\r\nHost: localhost\r\n\r\n')
    time.sleep(0.01)   # give server time to call inFlightCounter.add(1)
    s.close()          # sends RST — server never calls res.end()
EOF

# 4. Re-check counter — it will have increased by ~100 and will never decrease:
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total
# Expected: value is now ~100 higher than baseline, permanently.
```