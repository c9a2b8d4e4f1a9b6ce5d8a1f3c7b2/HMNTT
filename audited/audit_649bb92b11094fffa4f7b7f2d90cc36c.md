### Title
Unbounded Prometheus Label Cardinality via Unmatched Route Fallback in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates route-name extraction to the `weaveworks/common/middleware.Instrument` struct. When an incoming request does not match any registered gorilla/mux route, the weaveworks `Instrument` implementation falls back to using `r.RequestURI` (the raw request URI, including query string) as the `route` label value. Because Prometheus `GaugeVec` and `HistogramVec` never evict label-set entries once created, an unauthenticated attacker can drive unbounded memory growth by flooding the server with requests to distinct, unregistered paths.

### Finding Description
**Exact code path:**
- File: `rosetta/app/middleware/metrics.go`, lines 76–83
- All four metric vectors (`requestInflightGauge`, `requestDurationHistogram`, `requestBytesHistogram`, `responseBytesHistogram`) carry a `"route"` label.
- `MetricsMiddleware` constructs a `middleware.Instrument{RouteMatcher: next.(middleware.RouteMatcher)}` and calls `.Wrap(next)`.

**Root cause:**
The `weaveworks/common/middleware.Instrument` (version `v0.0.0-20230728070032-dd9e68f319d5`, declared in `rosetta/go.mod` line 25) resolves the route label via an internal `getRouteName` helper that calls `i.RouteMatcher.Match(r, &routeMatch)`. When the gorilla/mux router returns `false` (no registered route matches), the helper falls back to `r.RequestURI` — the full raw URI string including path and query string — as the label value. Every distinct URI therefore produces a brand-new label-set entry in each metric vector's internal `sync.Map`-backed store. Prometheus never removes these entries; they accumulate for the lifetime of the process.

**Failed assumption:**
The code assumes that `RouteMatcher` will always resolve requests to one of the small, fixed set of Rosetta API route names (e.g. `/network/list`, `/block`, `/construction/submit`). It does not account for the fallback path that exposes the raw URI to the label store.

**Exploit flow:**
1. Attacker sends HTTP requests to the Rosetta port (default 8080) with a continuously varying path, e.g. `POST /aaaa0001`, `POST /aaaa0002`, … or with varying query strings on any path.
2. None of these paths match any registered route; `RouteMatcher.Match` returns `false`.
3. `getRouteName` returns `r.RequestURI` for each request.
4. `requestInflightGauge.WithLabelValues(method, uniqueURI)` allocates a new `*dto.Metric` + internal map entry per unique URI.
5. The same allocation occurs in all three other metric vectors.
6. Entries are never evicted; heap grows monotonically.

**Why existing checks are insufficient:**
- No rate-limiting or request-throttling middleware is applied before `MetricsMiddleware` in `rosetta/main.go` lines 217–219.
- The HTTP server only sets `IdleTimeout`, `ReadHeaderTimeout`, `ReadTimeout`, and `WriteTimeout` (lines 221–226) — none of which limit the number of distinct paths an attacker can submit.
- The Rosetta asserter validates request bodies for matched routes, but `MetricsMiddleware` wraps the entire router and records the label *before* any route-level validation occurs.

### Impact Explanation
Continuous allocation of Prometheus label-set entries causes heap exhaustion. On a typical deployment, each unique label combination allocates several hundred bytes across four metric vectors (gauge + three histograms with 5–6 buckets each). Sending ~10 000 unique URIs per second is trivially achievable with a single HTTP client; at that rate the process accumulates tens of megabytes per second of non-reclaimable heap. The result is an out-of-memory kill of the Rosetta process, constituting a complete denial of service for all Rosetta API consumers (wallets, exchanges, block explorers).

### Likelihood Explanation
No authentication is required to reach the Rosetta HTTP port. The attack requires only the ability to open TCP connections and send HTTP requests — standard capability for any internet-accessible attacker. The attack is fully repeatable, requires no special knowledge of the application, and can be automated with a trivial loop. The Rosetta port is typically exposed to the internet or to a broad internal network segment.

### Recommendation
1. **Normalize unmatched routes to a fixed label value.** Wrap `MetricsMiddleware` with a custom `RouteMatcher` that returns a constant string (e.g. `"unmatched"`) when no route matches, preventing raw URIs from ever reaching the label store.
2. **Alternatively, replace `weaveworks/common/middleware.Instrument` with a custom middleware** that explicitly resolves the route name from the mux context after routing (using `mux.CurrentRoute(r)`) and substitutes a fixed sentinel for unmatched requests.
3. **Apply rate-limiting** (e.g. `golang.org/x/time/rate` or a reverse-proxy layer) before the metrics middleware to bound the rate at which new label-set entries can be created.
4. **Consider using `prometheus.MustCurryWith`** to pre-declare all valid route label values, so that `WithLabelValues` panics (or returns an error) for any label value not in the pre-declared set.

### Proof of Concept
```bash
# Requires: curl, bash
# Target: Rosetta node listening on localhost:8080

i=0
while true; do
  curl -s -o /dev/null -X POST "http://localhost:8080/exploit_path_${i}" \
       -H "Content-Type: application/json" -d '{}'
  i=$((i + 1))
done
```
Each iteration creates a new `route` label value (`/exploit_path_0`, `/exploit_path_1`, …) in all four Prometheus metric vectors. Monitor RSS growth with `ps -o rss= -p <pid>` — it will increase monotonically without bound. The process will be OOM-killed once available memory is exhausted.