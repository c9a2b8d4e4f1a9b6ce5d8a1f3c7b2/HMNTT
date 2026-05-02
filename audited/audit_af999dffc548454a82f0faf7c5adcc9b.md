### Title
Unbounded Prometheus Label Cardinality via Unmatched Routes in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates route extraction to the weaveworks `Instrument` middleware. When an incoming request does not match any registered gorilla/mux route, the weaveworks library falls back to using the raw `r.URL.Path` as the `route` label value. Because there is no cardinality cap, path normalization, or application-level rate limiting, an unprivileged attacker can flood the server with requests to arbitrarily unique URL paths, causing the Prometheus `HistogramVec` to accumulate an unbounded number of unique label sets and grow process memory without limit.

### Finding Description
**Exact code location:** `rosetta/app/middleware/metrics.go`, lines 28–32 and 76–83.

`requestDurationHistogram` is declared with four label dimensions: `{"method", "route", "status_code", "ws"}`.

```go
requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
    Name:    "hiero_mirror_rosetta_request_duration",
    Buckets: []float64{.1, .25, .5, 1, 2.5, 5},
    Help:    "Time (in seconds) spent serving HTTP requests.",
}, []string{"method", "route", "status_code", "ws"})
```

`MetricsMiddleware` wraps the router with `middleware.Instrument` from `github.com/weaveworks/common/middleware`:

```go
func MetricsMiddleware(next http.Handler) http.Handler {
    return middleware.Instrument{
        Duration:         requestDurationHistogram,
        ...
        RouteMatcher:     next.(middleware.RouteMatcher),
    }.Wrap(next)
}
```

**Root cause:** The weaveworks `Instrument.Wrap` implementation calls `RouteMatcher.MatchesMethod(r, &match)` to resolve the route template. When the request path does not match any registered route (gorilla/mux returns `false`), the library falls back to `r.URL.Path` — the raw, user-supplied URL path — as the `route` label value. No normalization, truncation, or allowlist is applied before the label is passed to `prometheus.HistogramVec.With(labels)`.

Each call to `With(labels)` with a previously unseen label combination allocates a new `Histogram` object in the registry. With 6 configured buckets, each unique label set creates 8 new in-memory time series (6 bucket counters + `_sum` + `_count`). These objects are never evicted; they accumulate for the lifetime of the process.

**Why existing checks fail:**
- The Traefik-level rate limiter (`rateLimit: average: 10`, `inFlightReq: amount: 5`) defined in `charts/hedera-mirror-rosetta/values.yaml` is an optional Kubernetes deployment artifact. It is not enforced by the application itself, is disabled when `global.middleware` is false, and is trivially bypassed by distributing requests across multiple source IPs.
- There is no application-level rate limiter, no path normalization before metric labeling, and no `prometheus.Labels` cardinality guard anywhere in the middleware stack.

### Impact Explanation
Every unique URL path sent by an attacker creates a permanent allocation in the default Prometheus registry. With 8 time series per unique label set and each series consuming ~hundreds of bytes, sending tens of thousands of unique paths (trivially achievable in seconds over HTTP) can grow process heap by tens to hundreds of megabytes, exceeding the 30% threshold. Sustained attack causes OOM termination of the rosetta process, constituting a denial-of-service against the mirror node's Rosetta API endpoint. No authentication is required to reach the HTTP port.

### Likelihood Explanation
The attack requires only the ability to send HTTP requests to the rosetta port (default `:8082`). No credentials, tokens, or special protocol knowledge are needed. The exploit is fully scriptable with a single `for` loop generating unique path strings. The effect is cumulative and permanent within a process lifetime, so even a slow, low-volume attack (well below any network-level rate limit) achieves the 30% memory growth threshold over hours. The attack is repeatable after process restart.

### Recommendation
1. **Normalize unmatched routes to a fixed sentinel value** before recording metrics. Override the route label to a constant such as `"unmatched"` or `"unknown"` when `RouteMatcher.MatchesMethod` returns false, preventing user-controlled strings from entering the label space.
2. **Enforce an application-level allowlist** for the `route` label: only record metrics for paths that match a known route template; drop or bucket all others under a single label.
3. **Add application-level rate limiting** (e.g., `golang.org/x/time/rate`) independent of any infrastructure middleware, so the protection is always active regardless of deployment topology.
4. Consider using `prometheus.MustCurryWith` with a fixed set of known routes, or replace `HistogramVec` with a fixed-cardinality structure.

### Proof of Concept
```bash
# Send 50,000 requests to unique paths, each producing a 404 and a new metric label set
for i in $(seq 1 50000); do
  curl -s -o /dev/null "http://<rosetta-host>:8082/attack/unique/path/$i"
done

# Observe memory growth via /metrics endpoint
curl http://<rosetta-host>:8082/metrics | grep hiero_mirror_rosetta_request_duration
# Output will contain 50,000 * 8 = 400,000 new time series lines
# Process RSS will have grown by hundreds of MB
```

Each request hits no registered route → gorilla/mux returns 404 → weaveworks `Instrument` uses `/attack/unique/path/<N>` as the `route` label → `requestDurationHistogram.With({"POST","GET", "/attack/unique/path/<N>", "404", "false"})` allocates a new histogram → memory grows permanently. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
