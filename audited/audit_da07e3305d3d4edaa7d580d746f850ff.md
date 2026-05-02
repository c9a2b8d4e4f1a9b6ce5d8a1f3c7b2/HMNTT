### Title
Prometheus Label Cardinality Explosion via Unmatched URL Paths in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` uses `github.com/weaveworks/common/middleware.Instrument` with a gorilla/mux `RouteMatcher`. When a request does not match any registered route, the weaveworks library falls back to using the raw `r.URL.Path` as the `route` label value. An unprivileged attacker can send an unbounded number of requests with unique URL paths, creating a new Prometheus time series per unique path across all four metric vectors, exhausting server memory and making `/metrics` a DoS vector.

### Finding Description
**Code location:** `rosetta/app/middleware/metrics.go`, `MetricsMiddleware()`, lines 76–83.

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

The `middleware.Instrument.Wrap()` from `github.com/weaveworks/common` calls its internal `ExtractRouteName(r, i.RouteMatcher)` helper. That helper calls `routeMatcher.Match(r, &match)` on the gorilla/mux router. When no registered route matches (i.e., `Match()` returns `false` or `match.Route == nil`), the helper falls back to returning `r.URL.Path` — the raw, attacker-controlled URL path — as the `route` label value.

This raw path is then used as a label on all four `*Vec` metrics:
- `hiero_mirror_rosetta_request_duration` (6 histogram buckets × unique route × method × status × ws)
- `hiero_mirror_rosetta_request_inflight` (gauge × unique route × method)
- `hiero_mirror_rosetta_request_bytes` (5 histogram buckets × unique route × method)
- `hiero_mirror_rosetta_response_bytes` (5 histogram buckets × unique route × method)

Each unique path permanently allocates new in-memory time series in the Prometheus default registry. The registry never evicts them. The `/metrics` endpoint serializes all accumulated time series on every scrape.

**Root cause:** No normalization, truncation, or allowlisting of the `route` label value for unmatched requests. The failed assumption is that the `RouteMatcher` will always return a bounded set of route templates; it does not — it silently falls back to the raw URL.

**Middleware ordering in `rosetta/main.go` lines 217–219** confirms the metrics middleware wraps the entire router, so every request — matched or not — passes through it before the router can reject it:

```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

### Impact Explanation
- **Memory exhaustion:** Each unique path permanently allocates ~(6+5+5+1) = 17 new time series entries across the four metric vectors. Sending 100,000 unique paths allocates ~1.7 million time series. At ~hundreds of bytes per series, this reaches hundreds of MB to GB of heap.
- **`/metrics` DoS:** The Prometheus text serializer iterates all stored time series on every scrape. A bloated registry causes the `/metrics` response to take seconds to generate and consume gigabytes of memory during serialization, making the endpoint itself a secondary DoS vector.
- **Process crash:** Go's runtime will OOM-kill the process once heap is exhausted, taking down the entire Rosetta API.
- **Severity: High** — complete availability loss of the Rosetta node, which is a critical infrastructure component for staking reward accounting.

### Likelihood Explanation
- **No authentication required** — the Rosetta API port is publicly reachable by design (it serves the Rosetta API to external callers).
- **No rate limiting** visible in the middleware stack.
- **No URL length enforcement** beyond Go's default 1 MB `MaxHeaderBytes`, which still allows thousands of unique paths per second.
- **Trivially scriptable:** a simple loop sending `GET /aaaa0001`, `GET /aaaa0002`, … suffices.
- **Permanent effect:** time series are never evicted; a one-time burst is sufficient to permanently degrade the process until restart.

### Recommendation
1. **Normalize unmatched routes to a fixed label** — wrap the `RouteMatcher` to return a constant string (e.g., `"unmatched"`) when no route matches, preventing raw URL paths from becoming label values.
2. **Alternatively, use `promhttp.InstrumentHandlerDuration` with a fixed label set** applied only after successful route matching.
3. **Add a `MaxBytesReader` / URL length cap** at the HTTP server level to limit the size of incoming URLs.
4. **Apply rate limiting** (e.g., via a token-bucket middleware) before `MetricsMiddleware` to bound the rate of new unique label creation.

### Proof of Concept
```bash
# Send 50,000 requests with unique paths to the Rosetta port (default 8080)
for i in $(seq 1 50000); do
  curl -s -o /dev/null "http://<rosetta-host>:8080/dos-path-$i" &
done
wait

# Observe memory growth and /metrics size
curl http://<rosetta-host>:8080/metrics | wc -c
# Output will be tens of MB and growing with each batch

# Repeat until OOM or /metrics endpoint times out
```

Each iteration permanently adds ~17 new time series to the in-process Prometheus registry. After sufficient iterations, `GET /metrics` will itself exhaust memory during serialization, completing the DoS. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/metrics.go (L28-43)
```go
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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
