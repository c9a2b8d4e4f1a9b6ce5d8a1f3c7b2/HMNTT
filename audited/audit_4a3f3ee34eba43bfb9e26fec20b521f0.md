### Title
Unbounded Prometheus Label Cardinality via Arbitrary HTTP Method Names in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates instrumentation to `weaveworks/common/middleware.Instrument`, which uses the raw `r.Method` value directly as the `method` label on all four Prometheus metric vectors. Go's `net/http` server accepts any RFC 7230-valid token as an HTTP method and passes it unmodified to handlers. An unauthenticated attacker can flood the service with requests bearing unique custom method names, creating an unbounded number of distinct label combinations in the Prometheus registry and exhausting process memory.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/metrics.go` lines 22–43 define four metric vectors all carrying a `"method"` label dimension: [1](#0-0) 

`MetricsMiddleware` (lines 76–84) wraps the router with `middleware.Instrument`, which internally reads `r.Method` verbatim and passes it as the `method` label value on every observation: [2](#0-1) 

The middleware is applied unconditionally to every inbound request before any routing or authentication occurs: [3](#0-2) 

**Root cause:** The `method` label is populated from the attacker-controlled `r.Method` field with no allowlist, normalization, or truncation. Go's `net/http` parser accepts any RFC 7230 token as a method name (e.g., `FOOBAR`, `XYZABC123`, `AAAA…N`) and delivers it to the handler unchanged. Each unique method string creates a new label-set entry in the `prometheus.HistogramVec` / `prometheus.GaugeVec` internal map. For a `HistogramVec` with 5 buckets, each new `(method, route)` pair allocates 7 new time-series objects (`_bucket{le=…}` ×5, `_count`, `_sum`). With four vectors, each unique method name yields ≥28 new heap-allocated objects that are never freed for the lifetime of the process.

**Why existing checks fail:**
- `ReadHeaderTimeout` / `ReadTimeout` (configured in `Http` struct) limit connection duration, not method-name cardinality across connections.
- `MaxHeaderBytes` (Go default 1 MB) limits a single request line but still permits thousands of distinct short method names across separate connections.
- No rate-limiting, method allowlisting, or label-value sanitization exists anywhere in the middleware chain. [4](#0-3) 

### Impact Explanation
Each unique method name permanently grows the Prometheus default registry's in-memory label-set map. Sustained flooding causes heap growth leading to OOM termination or severe GC pressure, rendering the Rosetta node unresponsive. Because the Rosetta node is a blockchain API gateway, its unavailability constitutes a network partition: clients and downstream systems lose the ability to submit or query transactions, directly violating the service's availability guarantee. Severity is **High** — complete denial of service achievable without authentication.

### Likelihood Explanation
The attack requires only the ability to send TCP connections to the Rosetta port (default publicly exposed). No credentials, valid Rosetta payloads, or prior knowledge of the API are needed. The exploit is trivially scriptable with `curl` or any HTTP client that allows custom method names. It is repeatable and persistent: label entries are never evicted, so even a low-rate drip of unique methods accumulates indefinitely. Any internet-exposed deployment is at risk.

### Recommendation
1. **Allowlist HTTP methods** before the metrics middleware: reject or normalize any method not in `{GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS, CONNECT, TRACE}` with a 405 response, so only a bounded set of values ever reaches the label.
2. **Normalize unknown methods** to a sentinel value (e.g., `"unknown"`) inside a thin wrapper around `MetricsMiddleware` before the label is recorded.
3. **Add rate limiting** (e.g., `golang.org/x/time/rate`) at the server entry point to bound the request rate per source IP, limiting the speed of cardinality inflation.
4. Consider setting `http.Server.MaxHeaderBytes` to a small value (e.g., 8 KB) to constrain method-name length.

### Proof of Concept
```bash
# Send 10 000 requests each with a unique custom HTTP method
for i in $(seq 1 10000); do
  curl -s -o /dev/null -X "CUSTOMMETHOD${i}" http://<rosetta-host>:<port>/network/list &
done
wait

# Observe Prometheus registry memory growth:
curl http://<rosetta-host>:<port>/metrics | grep -c 'hiero_mirror_rosetta_request_bytes_bucket'
# Count grows by 5 per unique method×route pair; heap usage climbs proportionally.

# With sufficient unique methods the process OOMs or becomes unresponsive:
# watch -n1 'ps -o rss= -p $(pgrep rosetta)'
```

Each loop iteration creates a new `method=CUSTOMMETHODn` label combination across all four metric vectors, permanently consuming heap. At scale this exhausts available memory and crashes or stalls the node.

### Citations

**File:** rosetta/app/middleware/metrics.go (L22-43)
```go
	requestBytesHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_request_bytes",
		Buckets: sizeBuckets,
		Help:    "Size (in bytes) of messages received in the request.",
	}, []string{"method", "route"})

	requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_request_duration",
		Buckets: []float64{.1, .25, .5, 1, 2.5, 5},
		Help:    "Time (in seconds) spent serving HTTP requests.",
	}, []string{"method", "route", "status_code", "ws"})

	requestInflightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hiero_mirror_rosetta_request_inflight",
		Help: "Current number of inflight HTTP requests.",
	}, []string{"method", "route"})

	responseBytesHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_response_bytes",
		Buckets: sizeBuckets,
		Help:    "Size (in bytes) of messages sent in response.",
	}, []string{"method", "route"})
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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
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
