### Title
Missing `res.on('close')` Guard Causes Permanent `inFlightCounter` Inflation on Client Abort

### Summary
In `rest/middleware/metricsHandler.js`, `metricsMiddleware()` increments `inFlightCounter` synchronously on every incoming request but only decrements it inside a `res.on('finish')` callback. In Node.js, the `'finish'` event is never emitted when a client aborts the TCP connection before the server calls `res.end()` — only the `'close'` event fires in that case. Because no `res.on('close')` fallback exists, each aborted request permanently inflates `api_all_request_in_processing_total` by +1 with no recovery path.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, function `metricsMiddleware()`:

- Line 169: `inFlightCounter.add(1)` — fires unconditionally for every non-metrics request, immediately upon receipt.
- Lines 185–186: `res.on('finish', () => { inFlightCounter.add(-1); … })` — the sole decrement site.

**Root cause / failed assumption:**

The code assumes `'finish'` is always emitted for every request that enters the middleware. This is false. Node.js `http.ServerResponse` inherits from `stream.Writable`. The `'finish'` event is emitted only after `res.end()` is called *and* all data has been flushed to the underlying socket. If the client closes the TCP connection before the server reaches `res.end()` (e.g., during a long-running DB query for Hashgraph history), the socket is destroyed, `res` emits `'close'` (not `'finish'`), and the `'finish'` listener is never invoked.

There is no `res.on('close', …)` handler anywhere in the middleware to serve as a fallback decrement.

**Exploit flow:**
1. Attacker sends `GET /api/v1/transactions?limit=100&…` (or any slow history endpoint).
2. Immediately after the TCP handshake completes and the HTTP request bytes are sent, attacker sends a TCP RST / closes the socket.
3. Node.js destroys the socket; `req` emits `'close'`; `res` emits `'close'`.
4. The server's async handler eventually calls `res.end()` on the dead socket — `'finish'` is never emitted.
5. `inFlightCounter` value is now permanently +1 higher than reality.
6. Repeat N times → counter is inflated by N with no self-correcting mechanism (the `UpDownCounter` has no TTL or sweep).

**Why existing checks are insufficient:**

There are no existing checks. The middleware contains exactly one decrement path (the `'finish'` listener) and no abort/close detection whatsoever.

### Impact Explanation
`api_all_request_in_processing_total` is an `UpDownCounter` (not a gauge with a scrape-time callback), so its value accumulates across the process lifetime. Each aborted request permanently adds +1. Operators and alerting rules (e.g., the Grafana panel querying `sum(api_all_request_in_processing_total{…})`) will observe a monotonically growing "requests in processing" value that never returns to zero. This:
- Masks real concurrency spikes (signal-to-noise destruction for on-call engineers).
- Can trigger false-positive capacity/overload alerts, causing unnecessary scaling or incident response.
- Prevents accurate SLO measurement for Hashgraph history query concurrency.

Severity: **Medium** — no direct data corruption or authentication bypass, but it permanently corrupts observability data and can indirectly cause operational harm.

### Likelihood Explanation
No authentication or rate-limiting is required to reach any REST API endpoint. Any unprivileged external user can open a TCP connection, send a valid HTTP request, and immediately close the socket. This is trivially scriptable with `curl --max-time 0`, `ab`, or raw socket tools. The attack is repeatable at high frequency (thousands of aborts per second from a single host), making unbounded counter inflation practical. The attacker needs zero knowledge of the system beyond the public API base URL.

### Recommendation
Replace the single `'finish'` listener with a once-guarded handler that also fires on `'close'`, ensuring exactly one decrement per request regardless of how the connection ends:

```javascript
// rest/middleware/metricsHandler.js  — inside metricsMiddleware()
let settled = false;
const onRequestEnd = () => {
  if (settled) return;
  settled = true;
  inFlightCounter.add(-1);
  // ... rest of metrics recording (duration, counters, histograms)
};

res.on('finish', onRequestEnd);  // normal completion
res.on('close',  onRequestEnd);  // client abort / socket destruction
```

The `settled` flag ensures the decrement and metric recording happen exactly once even if both events fire (which can occur in some Node.js versions when `res.end()` is called on a closing socket).

### Proof of Concept
```bash
# 1. Start the mirror-node REST service locally (default port 5551)

# 2. Send a request to a slow history endpoint and immediately abort:
for i in $(seq 1 100); do
  curl -s --max-time 0.001 \
    "http://localhost:5551/api/v1/transactions?limit=100&order=asc" \
    &>/dev/null || true
done

# 3. Scrape the metrics endpoint:
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total

# Expected (no bug): value near 0 after all requests complete
# Actual (with bug):  value is ~100 (one per aborted request), never decreasing
```

Each iteration of the loop increments the counter without a corresponding decrement, demonstrating permanent inflation by an unprivileged, unauthenticated external user.