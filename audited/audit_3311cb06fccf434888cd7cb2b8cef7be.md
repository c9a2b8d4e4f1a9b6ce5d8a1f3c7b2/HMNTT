### Title
Prometheus Label Cardinality Exhaustion via Unbounded `route` Label in MetricsMiddleware

### Summary
The `MetricsMiddleware` in `rosetta/app/middleware/metrics.go` instruments all four Prometheus metric vectors with a `route` label whose value is derived from the raw URL path when no registered route matches. Because `prometheus.HistogramVec` (and `GaugeVec`) never evict label-set entries, an unauthenticated attacker can drive unbounded heap growth by sending requests to an unlimited number of unique URL paths, eventually exhausting process memory and causing a denial of service.

### Finding Description

**Exact code location:** `rosetta/app/middleware/metrics.go`, lines 22–44 (metric vector declarations) and lines 76–84 (`MetricsMiddleware`).

All four metric vectors declare a `"route"` label with no cardinality bound:

```go
// lines 22-43
requestBytesHistogram    = prometheus.NewHistogramVec(..., []string{"method", "route"})
requestDurationHistogram = prometheus.NewHistogramVec(..., []string{"method", "route", "status_code", "ws"})
requestInflightGauge     = prometheus.NewGaugeVec(...,    []string{"method", "route"})
responseBytesHistogram   = prometheus.NewHistogramVec(..., []string{"method", "route"})
```

`MetricsMiddleware` wraps the router with `weaveworks/common/middleware.Instrument`:

```go
// lines 76-84
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

The weaveworks `Instrument.Wrap` calls its internal `ExtractRouteName` helper, which calls `RouteMatcher.MatchesRoutes(r)` on the gorilla/mux router. For any URL path that does not match a registered Rosetta route, `MatchesRoutes` returns `false`, and the library falls back to using `r.URL.Path` — the raw, attacker-controlled URL string — as the `route` label value.

Every distinct `(method, route [, status_code, ws])` tuple causes `prometheus.HistogramVec.With(labels)` to allocate a new internal `histogram` object (containing one counter per bucket plus sum/count). The Prometheus client library provides no TTL, LRU eviction, or maximum-cardinality enforcement; once created, a label-set entry lives for the lifetime of the process.

**Root cause / failed assumption:** The code assumes the `route` label will only ever take values from the finite set of registered Rosetta API paths. This assumption is violated for every unmatched request, because the weaveworks middleware substitutes the raw URL path rather than a fixed sentinel like `"unmatched"`.

**Exploit flow:**
1. Attacker sends `POST /aaaa`, `POST /aaab`, `POST /aaac`, … (or any enumeration of unique paths).
2. Each request passes through `MetricsMiddleware` before the router rejects it with 404.
3. `MatchesRoutes` returns `false`; weaveworks uses `r.URL.Path` as the `route` label.
4. `requestDurationHistogram.With(labels).Observe(...)` allocates a new histogram entry (6 buckets + sum + count = 8 int64/float64 values, plus map overhead) for each unique tuple.
5. With 4 metric vectors and 6 histogram buckets each, each unique path consumes ~hundreds of bytes of heap that is never freed.
6. After millions of unique paths the process OOMs.

**Existing checks reviewed and shown insufficient:**
- No rate limiting middleware is applied before `MetricsMiddleware` in `rosetta/main.go` (lines 217–219); the metrics instrumentation runs before any request validation.
- The gorilla/mux router's 404 handler fires *after* the weaveworks middleware has already recorded the label.
- There is no `MaxProcs`, label allowlist, or cardinality cap on any of the four metric vectors.

### Impact Explanation
An unauthenticated attacker who can reach the Rosetta HTTP port can cause the process to consume unbounded memory. Because the Rosetta node is a critical infrastructure component for blockchain exchange integrations (Coinbase Rosetta spec), crashing or degrading it disrupts block construction, transaction submission, and balance queries for any exchange or wallet relying on it. This is a non-network-based DoS (memory exhaustion) requiring no credentials.

### Likelihood Explanation
The attack requires only the ability to send HTTP POST/GET requests to the public Rosetta port — no authentication, no special headers, no valid JSON body. A single script generating unique URL paths at modest throughput (e.g., 10,000 req/s) can exhaust gigabytes of heap within minutes. The attack is repeatable across restarts unless the root cause is fixed, and is trivially automatable.

### Recommendation
1. **Normalize unmatched routes to a fixed label value.** Wrap the `RouteMatcher` to return a constant (e.g., `"unmatched"`) when `MatchesRoutes` returns `false`, preventing raw URL paths from ever reaching the label.
2. **Pre-initialize all valid label combinations** using `requestDurationHistogram.With(labels)` at startup for every known Rosetta route × method × status-code bucket, so the set of live label combinations is bounded by construction.
3. **Apply rate limiting** (e.g., `golang.org/x/time/rate`) before `MetricsMiddleware` to bound the rate at which new label combinations can be created even if normalization is incomplete.
4. Consider replacing `prometheus.NewHistogramVec` with a version that enforces a maximum cardinality and drops or aggregates excess label sets.

### Proof of Concept

```bash
# Send 1,000,000 requests with unique URL paths to the Rosetta server
# No authentication or valid body required; 404 responses are expected.
for i in $(seq 1 1000000); do
  curl -s -o /dev/null -X POST "http://<rosetta-host>:8080/unique/path/$i" &
done
wait

# Monitor heap growth:
# curl http://<rosetta-host>:8080/metrics | grep go_memstats_heap_inuse_bytes
# Observe monotonically increasing heap with no GC recovery.
```

Each iteration creates a new `route="/unique/path/<i>"` label entry in all four metric vectors. After sufficient iterations, the process will be OOM-killed or become unresponsive due to GC pressure. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/metrics.go (L28-32)
```go
	requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
		Name:    "hiero_mirror_rosetta_request_duration",
		Buckets: []float64{.1, .25, .5, 1, 2.5, 5},
		Help:    "Time (in seconds) spent serving HTTP requests.",
	}, []string{"method", "route", "status_code", "ws"})
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
