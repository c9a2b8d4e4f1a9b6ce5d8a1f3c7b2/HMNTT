### Title
Prometheus Label Cardinality Explosion via Arbitrary HTTP Method Strings in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates instrumentation to `weaveworks/common/middleware.Instrument`, which uses `r.Method` verbatim as the `method` label on all four Prometheus metric vectors. Go's `net/http` server accepts any valid HTTP token as a method, so an unauthenticated attacker can send requests with an unbounded set of distinct custom method strings, creating a new time-series for each unique value and causing unbounded memory growth in the Prometheus registry.

### Finding Description
**Exact code location:** `rosetta/app/middleware/metrics.go`, lines 76–83, `MetricsMiddleware()`.

```go
func MetricsMiddleware(next http.Handler) http.Handler {
    return middleware.Instrument{
        Duration:         requestDurationHistogram,   // labels: method, route, status_code, ws
        InflightRequests: requestInflightGauge,       // labels: method, route
        RequestBodySize:  requestBytesHistogram,      // labels: method, route
        ResponseBodySize: responseBytesHistogram,     // labels: method, route
        RouteMatcher:     next.(middleware.RouteMatcher),
    }.Wrap(next)
}
```

The `weaveworks/common/middleware.Instrument.Wrap()` (dependency pinned at `v0.0.0-20230728070032-dd9e68f319d5` in `rosetta/go.mod` line 25) reads `r.Method` directly from the incoming HTTP request and passes it as the `method` label value to all four metric vectors. There is no allowlist, normalization, or truncation of the method string anywhere in the middleware chain.

**Root cause / failed assumption:** The code assumes only a finite, standard set of HTTP methods (GET, POST, PUT, etc.) will ever appear in `r.Method`. This assumption is wrong: Go's `net/http` server accepts any syntactically valid HTTP token as a method and stores it verbatim in `r.Method`. The Prometheus `HistogramVec`/`GaugeVec` internals allocate a new internal time-series (with all its bucket counters) for every unique label combination observed.

**Exploit flow:**
1. Attacker sends HTTP requests to the Rosetta endpoint with distinct custom method strings: `METHOD1`, `METHOD2`, …, `METHODn`.
2. Go's HTTP server parses each method and sets `r.Method = "METHODn"`.
3. The weaveworks `Instrument` middleware fires before the router rejects the request (405), records the duration, and calls `requestDurationHistogram.With(prometheus.Labels{"method": "METHODn", "route": "...", ...}).Observe(...)`.
4. Prometheus allocates a new internal `*histogram` object (with 6 buckets + sum + count = 8 counters) per unique `(method, route, status_code, ws)` combination.
5. Repeated with N distinct method strings → N new time-series per metric vector → O(4N) total allocations, growing without bound.

**Why existing checks are insufficient:** There are no checks. The middleware has no method allowlist, no label-value sanitization, and no cardinality cap. The router (gorilla/mux via `coinbase/rosetta-sdk-go`) does reject non-POST requests with 405, but this rejection happens *inside* the wrapped handler — after the weaveworks middleware has already recorded the metric with the attacker-controlled method label.

### Impact Explanation
Each unique method string permanently allocates memory in the Prometheus default registry for the lifetime of the process. With 6 duration buckets, 5 size buckets, and 4 metric vectors, each new method value allocates dozens of atomic counters. Sustained attack with millions of distinct method strings causes the process to exhaust heap memory and crash (OOM), constituting a denial-of-service against the Rosetta node. Additionally, the `/metrics` scrape endpoint (line 70, `promhttp.Handler().ServeHTTP`) will return an ever-growing response, degrading the monitoring pipeline.

### Likelihood Explanation
No authentication is required to reach `MetricsMiddleware` — it wraps all incoming HTTP traffic. Sending custom HTTP methods requires only a raw TCP connection or a tool like `curl --request CUSTOMMETHOD`. The attack is trivially scriptable: a loop sending `METHOD1` through `METHOD1000000` requires no special privileges, no credentials, and no knowledge of the application beyond its open port. It is repeatable and persistent (allocations are never freed).

### Recommendation
Normalize the `method` label to a fixed allowlist before it reaches Prometheus. In the application layer, wrap the method extraction with a sanitizer:

```go
func sanitizeMethod(m string) string {
    switch strings.ToUpper(m) {
    case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
        return strings.ToUpper(m)
    default:
        return "unknown"
    }
}
```

Since the weaveworks `Instrument` struct reads `r.Method` internally, the cleanest fix is to add a pre-middleware that rewrites `r.Method` to the sanitized value before the request reaches `MetricsMiddleware`, or to replace the weaveworks instrumentation with a custom handler that applies the sanitizer explicitly before calling `requestDurationHistogram.With(...)`.

### Proof of Concept
```bash
# Send 10,000 requests with distinct custom HTTP methods
for i in $(seq 1 10000); do
  curl -s -o /dev/null -X "CUSTOMMETHOD${i}" http://<rosetta-host>:<port>/network/list \
    -H "Content-Type: application/json" -d '{}'
done

# Observe memory growth and metric count explosion
curl http://<rosetta-host>:<port>/metrics | grep -c 'hiero_mirror_rosetta_request_duration_bucket'
# Returns a count proportional to the number of unique methods sent
```

Each iteration creates a new `method=CUSTOMMETHODn` label combination across all four metric vectors, permanently consuming process memory. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/metrics.go (L28-32)
```go
	requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_request_duration",
		Buckets: []float64{.1, .25, .5, 1, 2.5, 5},
		Help:    "Time (in seconds) spent serving HTTP requests.",
	}, []string{"method", "route", "status_code", "ws"})
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

**File:** rosetta/go.mod (L25-25)
```text
	github.com/weaveworks/common v0.0.0-20230728070032-dd9e68f319d5
```
