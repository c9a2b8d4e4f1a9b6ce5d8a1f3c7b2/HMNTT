### Title
`inFlightCounter` Permanent Leak via Missing `res.on('close')` Handler Allows Metric Inflation by Any Unprivileged User

### Summary
In `rest/middleware/metricsHandler.js`, `inFlightCounter.add(1)` is called unconditionally for every non-metrics request (line 169), but the sole decrement `inFlightCounter.add(-1)` lives exclusively inside a `res.on('finish')` handler (line 186). In Node.js HTTP, the `finish` event only fires when `res.end()` completes successfully; if the client closes the TCP connection before the server sends the response, the `close` event fires instead and `finish` never fires. Because no `res.on('close')` handler exists, the counter is permanently incremented for every such aborted request. Any unprivileged external user can repeat this at will, driving `api_all_request_in_processing_total` to an arbitrarily large value.

### Finding Description
**Exact code path:**
- `rest/middleware/metricsHandler.js`, `metricsHandler()` → inner `metricsMiddleware(req, res, next)`
- Line 169: `inFlightCounter.add(1)` — unconditional increment on every instrumented request.
- Lines 185–211: `res.on('finish', () => { inFlightCounter.add(-1); … })` — the only decrement.

**Root cause / failed assumption:**
The code assumes `finish` is always emitted for every request that passes line 169. This is false. Node.js `http.ServerResponse` emits `finish` only after `res.end()` successfully flushes data to the OS. If the underlying socket is destroyed first (client abort, RST packet, network drop), Node.js emits `close` on the response object and `finish` is never emitted. There is no `res.on('close', ...)` handler anywhere in the function to compensate.

**Exploit flow:**
1. Attacker opens a TCP connection to any API endpoint (e.g., `GET /api/v1/transactions`).
2. Server receives the request; line 169 fires: `inFlightCounter.add(1)`.
3. Attacker immediately sends a TCP RST or closes the socket before the server writes the response.
4. Node.js emits `close` on `res`; `finish` is never emitted.
5. `inFlightCounter.add(-1)` is never called; the counter is now permanently +1.
6. Attacker repeats steps 1–5 in a tight loop (no authentication required, no rate-limit specific to this path in the shown code).

**Why existing checks are insufficient:**
- The `authenticate()` check (lines 137–144) only guards the `/metrics/` scrape endpoint, not the instrumented request path.
- There is no `res.on('close')` handler, no `try/finally` around the counter, and no periodic reconciliation of the counter value.

### Impact Explanation
The `api_all_request_in_processing_total` Prometheus metric becomes permanently inflated. Operators and alerting rules that rely on this gauge to detect anomalous load or to correlate in-flight request counts with authorization activity will see a falsely elevated baseline. This can mask real spikes (alert fatigue / threshold bypass) or, conversely, trigger false-positive incidents that consume operator attention while actual suspicious authorization activity goes unnoticed. The counter is an `UpDownCounter` (line 83) so it never auto-resets; the only recovery is a process restart.

### Likelihood Explanation
Exploitation requires zero privileges — any HTTP client can abort a connection. The technique (send request, immediately RST) is trivially scriptable with tools like `curl`, `hping3`, or raw sockets. It is repeatable at high frequency from a single host or distributed across many IPs. No special knowledge of the application is needed beyond knowing any valid URL path. The condition (client disconnect before server response) occurs naturally under normal load as well, meaning the leak also accumulates organically without deliberate attack.

### Recommendation
Add a `res.on('close')` handler that decrements the counter only if `finish` has not already fired:

```js
// rest/middleware/metricsHandler.js  ~line 185
let finished = false;

res.on('finish', () => {
  finished = true;
  inFlightCounter.add(-1);
  // … rest of metrics recording …
});

res.on('close', () => {
  if (!finished) {
    inFlightCounter.add(-1);
  }
});
```

This ensures exactly one decrement per increment regardless of whether the connection is cleanly finished or abruptly closed.

### Proof of Concept
```bash
# Requires: bash, curl (or any tool that can abort mid-connection)
# Target: any API endpoint, no credentials needed

for i in $(seq 1 500); do
  # Connect, send request headers, then immediately close with --max-time 0
  curl -s --max-time 0.001 http://<mirror-node-host>/api/v1/transactions &
done
wait

# Now scrape metrics (if accessible) and observe inflated counter:
curl -u admin:password http://<mirror-node-host>/swagger/metrics/ \
  | grep api_all_request_in_processing_total
# Expected: value >> 0 and growing, never returning to baseline
```

Each iteration increments `inFlightCounter` at line 169 and aborts before `res.on('finish')` fires, leaving the counter permanently elevated by the number of aborted requests. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest/middleware/metricsHandler.js (L83-85)
```javascript
  inFlightCounter = meter.createUpDownCounter('api_all_request_in_processing_total', {
    description: 'Number of requests currently being processed',
  });
```

**File:** rest/middleware/metricsHandler.js (L169-169)
```javascript
    inFlightCounter.add(1);
```

**File:** rest/middleware/metricsHandler.js (L185-186)
```javascript
    res.on('finish', () => {
      inFlightCounter.add(-1);
```
