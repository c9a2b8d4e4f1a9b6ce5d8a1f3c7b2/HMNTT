### Title
Prometheus Label Cardinality Explosion via Unmatched Route Path Injection in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates route-label extraction to `github.com/weaveworks/common/middleware.Instrument`. When a request path does not match any registered gorilla/mux route, the weaveworks `Instrument` falls back to using the raw `r.URL.Path` as the `route` label value. An unauthenticated attacker can flood the server with requests carrying unique, arbitrary paths (including path-traversal variants such as `/../../../a`, `/../../../b`, …) to create an unbounded number of distinct Prometheus label combinations across all four registered metric vectors, exhausting process memory and degrading or crashing the Prometheus scrape pipeline.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/metrics.go`, lines 76–83:

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

**Root cause:**

`middleware.Instrument.Wrap` (weaveworks `v0.0.0-20230728070032-dd9e68f319d5`) calls `RouteMatcher.MatchesRouteOf(r)` to obtain the route template. For gorilla/mux (used by `github.com/coinbase/rosetta-sdk-go/server`), `MatchesRouteOf` returns an empty string when no registered route matches the request path. The weaveworks middleware then falls back to `r.URL.Path` — the raw, user-supplied path — as the `route` label value. No sanitization, normalization, or cardinality cap is applied anywhere in the application code.

**Exploit flow:**

1. Attacker sends HTTP POST/GET requests with unique paths that do not match any registered route (e.g., `POST /../../../a`, `POST /../../../b`, `POST /x1`, `POST /x2`, …).
2. Go's `net/http` server passes the raw path to the handler chain without cleaning it (path cleaning only occurs in `http.ServeMux`, not when a custom handler is used directly — as is the case here, see `rosetta/main.go` line 217: `metricsMiddleware := middleware.MetricsMiddleware(router)`).
3. Gorilla/mux's `MatchesRouteOf` cleans the path internally for matching purposes but returns `""` because no route matches.
4. The weaveworks `Instrument` records `r.URL.Path` (e.g., `/../../../a`) as the `route` label.
5. Each unique path value creates new in-memory time-series entries across all four `HistogramVec`/`GaugeVec` objects. `requestDurationHistogram` alone has 6 buckets × N unique `(method, route, status_code, ws)` combinations.

**Why existing checks fail:**

- The Traefik rate-limit (`average: 10`, `values.yaml` line 157–160) is an optional Kubernetes deployment artifact; it is not enforced at the Go application layer and is absent in bare-metal or Docker deployments.
- The in-flight limit (`amount: 5`) throttles concurrency but does not bound the total number of unique label values accumulated over time.
- There is no `MaxCardinality` option set on any of the four metric vectors, and the Prometheus client library has no built-in cardinality cap.

### Impact Explanation

Each unique `route` label value permanently allocates memory for histogram buckets and internal Prometheus registry structures. With 4 metric vectors and up to 6+1 buckets per histogram, each unique path injects ~30–50 new time-series objects. Sustained injection of thousands of unique paths causes heap growth leading to OOM termination of the rosetta process, or severe Prometheus scrape latency/failure. This constitutes a non-network-based DoS (resource exhaustion) against the mirror node's observability and availability.

### Likelihood Explanation

The attack requires no authentication, no special headers, and no knowledge of the application internals — only the ability to send HTTP requests to the rosetta port. It is trivially scriptable:

```bash
for i in $(seq 1 10000); do
  curl -s -o /dev/null "http://<rosetta-host>:8080/../../$RANDOM/$RANDOM"
done
```

Even at 10 req/s (Traefik rate limit), 10,000 unique label values are injected in ~17 minutes. The attack is repeatable and persistent (labels are never evicted from the Prometheus registry at runtime).

### Recommendation

1. **Normalize the route label for unmatched paths**: Wrap `RouteMatcher` to return a fixed sentinel string (e.g., `"unmatched"`) instead of the raw path when no route matches, preventing user-controlled values from becoming label values.
2. **Use `prometheus.MustRegister` with a cardinality-limiting wrapper** or replace `NewHistogramVec` with a version that enforces a maximum number of label combinations.
3. **Apply path cleaning before label extraction**: Use `path.Clean(r.URL.Path)` and validate against a whitelist of known route prefixes before recording.
4. **Enforce rate limiting at the application layer** (not only at the ingress/Traefik layer) so it applies regardless of deployment topology.

### Proof of Concept

```bash
#!/bin/bash
# Inject 5000 unique route labels into Prometheus via unmatched paths
ROSETTA="http://localhost:8080"
for i in $(seq 1 5000); do
  curl -s -o /dev/null -X POST \
    -H "Content-Type: application/json" \
    -d '{}' \
    "${ROSETTA}/../../unique_path_${i}/inject"
done

# Verify cardinality explosion
curl -s http://localhost:8080/metrics | grep hiero_mirror_rosetta_request_duration | wc -l
# Expected: thousands of unique time-series lines
```

**Preconditions:** Network access to the rosetta HTTP port (default 8080). No credentials required.
**Trigger:** Each request with a unique unmatched path creates a new `route` label value.
**Result:** Prometheus registry memory grows unboundedly; scrape endpoint becomes slow or OOM kills the process.