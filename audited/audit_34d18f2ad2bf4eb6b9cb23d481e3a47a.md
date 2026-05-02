### Title
Prometheus Label Cardinality Explosion via Unbounded `route` Label in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates route extraction to the weaveworks `middleware.Instrument`, which falls back to using the raw request URI as the `route` label value when no registered route matches. Because any unprivileged external user can send HTTP requests to arbitrary URL paths, each unique path creates a new set of Prometheus time-series entries across all four `HistogramVec`/`GaugeVec` metrics, causing unbounded heap growth in the process's Prometheus registry.

### Finding Description
**Code location:** `rosetta/app/middleware/metrics.go`, `MetricsMiddleware()`, lines 76–84.

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

All four metrics use a `{"method", "route"}` label set (plus `{"status_code", "ws"}` for `requestDurationHistogram`). The `route` label value is populated by the weaveworks `middleware.Instrument.Wrap` internals via `ExtractRouteName(i.RouteMatcher, r)`. When `RouteMatcher.MatchHTTPRoutes(r)` returns `nil` (i.e., no registered route matches the incoming request), the weaveworks library falls back to `r.RequestURI` as the route label value. This is the documented fallback behavior of `github.com/weaveworks/common/middleware`.

The Rosetta server is built with `server.NewRouter` (gorilla/mux under the hood) and registers a fixed, finite set of Rosetta API endpoints. Any request to a path outside that set (e.g., `/foo`, `/aaa/bbb`, `/x1`, `/x2`, …) will not match, causing the raw URL path to be used as the `route` label.

Each unique `(method, route)` pair causes the Prometheus client library to allocate a new internal `metricWithLabelValues` entry in the `HistogramVec`/`GaugeVec` internal map, which is never evicted. For histograms with 5 buckets, each new time-series allocates 7 internal counters (`_bucket×5`, `_sum`, `_count`). With four metrics and N unique paths, the total in-memory entries grow as `N × (7 + 8 + 1 + 7) = N × 23`.

**Why existing checks fail:**
- The Traefik `rateLimit` and `inFlightReq` middleware (defined in `charts/hedera-mirror-rosetta/values.yaml`, lines 152–161) are optional Kubernetes-level infrastructure components, not enforced at the Go application layer. A direct connection to the service port bypasses them entirely.
- There is no application-level rate limiting, no maximum cardinality cap on any of the four `HistogramVec`/`GaugeVec` metrics, and no sanitization/normalization of the `route` label value before it is passed to Prometheus.
- The `method` label is bounded (finite HTTP verbs), but `route` is fully attacker-controlled for unmatched paths.

### Impact Explanation
An attacker sending N unique URL paths causes the Go process heap to grow proportionally to N. With 100,000 unique paths, approximately 2.3 million Prometheus internal counter objects are allocated and never freed, easily exceeding a 30% heap increase threshold. Sustained attack leads to OOM termination of the Rosetta node, denying service to all legitimate users. The attack also degrades `/metrics` scrape performance as the Prometheus registry must iterate over an ever-growing label map.

### Likelihood Explanation
The Rosetta API is a public HTTP service (port 5700 per the workflow configuration). No authentication is required to send arbitrary HTTP requests. The attack requires only a simple HTTP client in a loop generating unique path strings. It is fully automatable, repeatable, and requires zero privileges. The attacker does not need a valid Rosetta request body; a bare `GET /x1`, `GET /x2`, … suffices to trigger metric recording for each unique path.

### Recommendation
1. **Normalize unmatched routes to a fixed label value**: Wrap the `RouteMatcher` to return a fixed string (e.g., `"unmatched"`) when no route matches, preventing raw URL paths from reaching the `route` label.
2. **Replace `middleware.Instrument` with a custom middleware** that explicitly maps the matched gorilla/mux route template to the label, and uses a static fallback for non-matching requests.
3. **Add a Prometheus label cardinality guard**: Use `prometheus.WrapRegistererWithPrefix` combined with a custom `Registerer` that panics or drops metrics beyond a configurable cardinality limit.
4. **Enforce rate limiting at the application layer** (e.g., `golang.org/x/time/rate`) independent of infrastructure-level Traefik configuration.

### Proof of Concept
```bash
# Send 50,000 requests with unique paths to the Rosetta node
for i in $(seq 1 50000); do
  curl -s -o /dev/null "http://<rosetta-host>:5700/attack-path-$i" &
done
wait

# Observe heap growth via /metrics endpoint
curl http://<rosetta-host>:5700/metrics | grep "go_memstats_heap_inuse_bytes"

# Confirm unbounded time-series accumulation
curl http://<rosetta-host>:5700/metrics | grep "hiero_mirror_rosetta_response_bytes_bucket" | wc -l
# Expected: count grows linearly with number of unique paths sent
```