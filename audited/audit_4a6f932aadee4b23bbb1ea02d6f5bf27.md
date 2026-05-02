### Title
Unbounded `inFlightCounter` Growth via Aborted Connections in `metricsMiddleware`

### Summary
In `rest/middleware/metricsHandler.js`, `metricsMiddleware()` unconditionally increments `inFlightCounter` on every incoming request but only decrements it inside a `res.on('finish')` handler. In Node.js, the `finish` event does not fire when a client closes the TCP connection (RST/FIN) before the server completes writing the response — the `close` event fires instead. Because no `close` handler exists, each such aborted request permanently leaks `+1` into `api_all_request_in_processing_total`, allowing any unprivileged attacker to drive the gauge unboundedly upward.

### Finding Description
**Exact code path:**

- `rest/middleware/metricsHandler.js`, `metricsMiddleware()`, line 169: `inFlightCounter.add(1)` — called unconditionally for every non-metrics request.
- Lines 185–186: `res.on('finish', () => { inFlightCounter.add(-1); … })` — the **sole** decrement site.
- No `res.on('close', …)` or `req.on('close', …)` handler exists anywhere in the file or in `rest/**/*.js` (confirmed by grep).

**Root cause:**  
Node.js's `http.ServerResponse` emits `finish` only after `res.end()` has been called and the data has been flushed to the OS send buffer. When a client sends a TCP RST or FIN before the server reaches `res.end()` (e.g., during a long-running DB query), the OS closes the socket; the subsequent write attempt fails with `EPIPE`; the writable stream emits `error` or `close` — **not** `finish`. The failed assumption is that `finish` is always guaranteed to fire for every request that entered the middleware.

**Exploit flow:**
1. Attacker sends `GET /api/v1/contracts/{id}/results` (or any slow endpoint involving multiple DB round-trips, e.g., `getContractResults` at `contractController.js:1050` which fans out to `getContractResultsByIdAndFilters` + `getEthereumTransactionsByPayerAndTimestampArray` + `getRecordFileBlockDetailsFromTimestampArray`).
2. Line 169 fires: `inFlightCounter.add(1)`.
3. Attacker immediately closes the TCP connection (RST).
4. Server is mid-query; when it eventually calls `res.end()`, the socket is already closed; write fails.
5. `finish` never fires → `inFlightCounter.add(-1)` is never called.
6. Repeat at high volume; counter grows without bound.

**Why existing checks are insufficient:**  
There are no rate-limiting or connection-throttling controls in `metricsMiddleware` itself. The metrics path is the only branch that bypasses instrumentation (lines 156–165); all other paths unconditionally increment the counter. There is no guard, deduplication flag, or `close`-event fallback.

### Impact Explanation
`api_all_request_in_processing_total` is an `UpDownCounter` (line 83) intended to reflect the real-time number of in-flight requests. An attacker can inflate it to arbitrarily large values, causing:
- Monitoring/alerting systems that threshold on this gauge to fire continuous false-positive alerts.
- Legitimate spikes in smart contract processing load to be invisible against the inflated baseline, masking real anomalies (e.g., a surge in contract execution errors or latency).
- Operator fatigue leading to suppressed alerts, reducing incident response effectiveness.

No funds are directly at risk, but the integrity of the observability layer for smart contract endpoints is compromised. Severity: **Medium**, consistent with the stated scope classification.

### Likelihood Explanation
No authentication or privilege is required — the endpoints are public. The attack requires only a TCP client capable of sending a request and immediately resetting the connection (trivially done with `curl`, `hping3`, or a raw socket script). The slow contract-result endpoints provide a reliable window for the race condition. The attack is fully repeatable and automatable at high volume from a single host.

### Recommendation
Listen to both `finish` and `close` on the response, using a one-shot flag to ensure the decrement fires exactly once regardless of which event arrives first:

```js
res.on('finish', () => {
  inFlightCounter.add(1);   // ← replace with the pattern below
});
```

Replace the `res.on('finish', …)` block with:

```js
let settled = false;
const settle = () => {
  if (settled) return;
  settled = true;
  inFlightCounter.add(-1);
  // … rest of metric recording …
};
res.on('finish', settle);
res.on('close',  settle);   // fires on premature client disconnect
```

This ensures `inFlightCounter` is always decremented exactly once per request, regardless of whether the connection was cleanly finished or abruptly closed.

### Proof of Concept

```bash
# Requires: a running mirror-node REST instance at localhost:5551
# and a contract ID that triggers a slow multi-join query.

# Step 1 – baseline: read current gauge value
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total

# Step 2 – flood with aborted connections (1000 requests, each killed after 1 ms)
for i in $(seq 1 1000); do
  curl -s --max-time 0.001 \
    "http://localhost:5551/api/v1/contracts/0.0.1234/results" \
    > /dev/null 2>&1 &
done
wait

# Step 3 – observe inflated gauge (should be >> 0 even after all requests complete)
curl -s http://localhost:5551/swagger/metrics/ | grep api_all_request_in_processing_total
```

Expected: the gauge value after step 3 is significantly higher than after step 1 and does not return to 0, confirming the permanent leak.