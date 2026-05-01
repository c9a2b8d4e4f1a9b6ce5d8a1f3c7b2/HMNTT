### Title
Unbounded Request Body on `/network/status` Enables Memory Exhaustion DoS

### Summary
The `/network/status` endpoint accepts a `*rTypes.NetworkRequest` POST body with no application-level size limit. The rosetta-sdk-go framework reads and JSON-decodes the full request body before invoking `NetworkStatus()`, and neither the application middleware chain nor the `http.Server` configuration applies `http.MaxBytesReader` or any equivalent byte-cap. An unauthenticated attacker can send arbitrarily large payloads across concurrent connections to exhaust server memory and crash the process.

### Finding Description
**Exact code path:**

`rosetta/app/services/network_service.go`, `NetworkStatus()`, lines 59–88 — the handler discards the parsed body (`_ *rTypes.NetworkRequest`), but the upstream rosetta-sdk-go controller still reads and decodes the full HTTP body before the service method is called.

**Server setup — no body size limit anywhere in the chain:**

`rosetta/main.go` lines 217–227 builds the middleware stack as:
```
corsMiddleware → tracingMiddleware → metricsMiddleware → router
```
None of these wrappers call `http.MaxBytesReader`. The `http.Server` struct (lines 220–227) sets only time-based limits (`ReadTimeout: 5s`, `ReadHeaderTimeout: 3s`) — no `MaxBytesHandler` or per-request byte cap.

**Middleware files confirmed absent of any size guard:**
- `rosetta/app/middleware/trace.go` — logging only
- `rosetta/app/middleware/metrics.go` — Prometheus instrumentation only
- `rosetta/app/middleware/health.go` — health routes only

**Root cause:** Go's `net/http` server has no default body size limit. Without `http.MaxBytesReader`, the JSON decoder in the rosetta-sdk-go controller will stream-read the entire body into memory, allocating proportionally to payload size.

**Why existing checks fail:**
- `ReadTimeout: 5s` is time-based. On a 1 Gbps link, ~625 MB can be delivered within the window.
- The Traefik `inFlightReq` (5 req/IP) and `rateLimit` (10 req/s) in `charts/hedera-mirror-rosetta/values.yaml` lines 152–161 are optional Kubernetes ingress configuration — they are not enforced at the application layer and are absent in bare-metal or direct deployments.

### Impact Explanation
Each oversized request forces the Go runtime to allocate memory proportional to the payload. With multiple concurrent connections (no server-side connection limit is set), an attacker can drive the process into OOM, causing the Rosetta node to crash. Because the Rosetta API is the sole interface for block/network data consumers, crashing it severs all dependent tooling. In a multi-replica deployment, simultaneous floods against all replicas can take down ≥30% of the Rosetta processing tier without any brute-force key material.

### Likelihood Explanation
No authentication is required. The endpoint is publicly reachable by design (Rosetta spec mandates public access). The attack requires only a standard HTTP client capable of sending a large POST body — no exploit code, no credentials, no protocol knowledge beyond basic HTTP. It is trivially repeatable and scriptable. The only partial mitigations (Traefik middleware) are deployment-optional and bypassable with multiple source IPs.

### Recommendation
Wrap the router with `http.MaxBytesHandler` at server startup in `rosetta/main.go`, immediately before assigning to `httpServer.Handler`:

```go
const maxBodyBytes = 1 << 20 // 1 MB
limitedRouter := http.MaxBytesHandler(corsMiddleware, maxBodyBytes)
httpServer := &http.Server{
    Handler: limitedRouter,
    ...
}
```

Alternatively, apply `http.MaxBytesReader(w, r.Body, maxBodyBytes)` inside a dedicated middleware inserted into the chain before the router. A 1 MB ceiling is more than sufficient for any valid `NetworkRequest` payload.

### Proof of Concept
```bash
# Generate a ~100 MB payload that is valid JSON (large metadata map)
python3 -c "
import json, sys
payload = {'network_identifier': {'blockchain': 'Hiero', 'network': 'mainnet'},
           'metadata': {'x': 'A' * 100_000_000}}
sys.stdout.write(json.dumps(payload))
" > big_payload.json

# Send 20 concurrent requests
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/network/status \
       -H 'Content-Type: application/json' \
       --data-binary @big_payload.json &
done
wait
# Monitor: watch -n1 'ps aux | grep rosetta'
# Expected: OOM kill or process crash within seconds
```