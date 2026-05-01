### Title
Unbounded HTTP Method Label Cardinality in `MetricsMiddleware` Enables Memory Exhaustion DoS

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` delegates instrumentation to `github.com/weaveworks/common/middleware.Instrument`, which uses the raw `r.Method` value directly as the `method` Prometheus label with no allowlist or normalization. An unauthenticated attacker can flood the Rosetta node with requests bearing arbitrary HTTP method tokens, creating an unbounded number of unique Prometheus time series across all four metric vectors, exhausting process memory and crashing the node. This makes the Rosetta node unable to serve transaction history responses.

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

`rosetta/main.go`, lines 217–219 (middleware chain):
```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware    := server.CorsMiddleware(tracingMiddleware)
```

**Root cause:** The `weaveworks/common/middleware.Instrument.Wrap()` implementation extracts the HTTP method label directly from `r.Method` with no normalization or allowlist. Every unique string used as an HTTP method token produces a new label combination in each of the four `prometheus.HistogramVec`/`GaugeVec` instances. Prometheus stores each unique label combination as a separate in-memory time series (with full bucket arrays for histograms). There is no cap on the number of label combinations.

**Failed assumption:** The code assumes the `method` label has bounded cardinality (GET, POST, etc.). Go's `net/http` server accepts any syntactically valid HTTP token as a method and sets `r.Method` to that string verbatim. The router (gorilla/mux via coinbase/rosetta-sdk-go) returns 405 for unregistered methods, but the weaveworks `Instrument` middleware records metrics *before* the router's response is finalized — the inflight gauge is incremented and the duration/bytes histograms are observed for every request regardless of status.

**Why existing checks fail:**
- `CorsMiddleware` (outermost) does not restrict HTTP methods.
- `TracingMiddleware` logs `r.Method` but applies no restriction.
- `MetricsMiddleware` / weaveworks `Instrument` has no method allowlist.
- The gorilla/mux router's 405 rejection happens *inside* the instrumented handler, after metrics labels are already committed.
- No rate limiting exists anywhere in the chain.

### Impact Explanation

Each unique method string multiplies across four metric vectors. `requestDurationHistogram` alone has 6 buckets × N unique `(method, route, status_code, ws)` combinations. With thousands of unique method strings, the Prometheus default registry accumulates tens of thousands of live time series, each holding allocated bucket arrays. Sustained attack causes heap growth until the Go runtime OOM-kills the process. When the Rosetta node crashes, all in-flight `/block/transaction` and `/block` responses are dropped, and clients that rely on sequential polling of the node for transaction history lose their place in the sequence — effectively disrupting the integrity of transaction history delivery.

**Severity:** High (unauthenticated network-reachable DoS against a blockchain infrastructure node).

### Likelihood Explanation

Preconditions: none. The Rosetta port is network-accessible by design (it serves the Rosetta API). Any HTTP client can send arbitrary method tokens. The attack is trivially scriptable, requires no credentials, no knowledge of internal state, and is repeatable indefinitely. A single attacker with a modest script cycling through unique method strings (e.g., `METHOD00001`, `METHOD00002`, …) can exhaust memory within minutes depending on available RAM.

### Recommendation

1. **Normalize the method label** before it reaches Prometheus. Wrap `MetricsMiddleware` with a sanitizing adapter that replaces any method not in `{GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, CONNECT, TRACE}` with the literal string `"unknown"`:

```go
func sanitizeMethod(m string) string {
    switch m {
    case "GET", "POST", "PUT", "PATCH", "DELETE",
         "HEAD", "OPTIONS", "CONNECT", "TRACE":
        return m
    default:
        return "unknown"
    }
}
```

Apply this before the `r.Method` value reaches the weaveworks `Instrument` (e.g., via a thin wrapping `http.Handler` that rewrites `r.Method` on a shallow copy of the request before passing it to `MetricsMiddleware`).

2. **Add rate limiting** (e.g., `golang.org/x/time/rate`) at the outermost handler to bound the request rate per source IP.

3. Consider replacing the weaveworks `Instrument` with a custom instrumentation wrapper that explicitly controls which label values are permitted.

### Proof of Concept

```bash
# Flood the Rosetta node with unique HTTP methods, each creating new Prometheus label combinations
for i in $(seq 1 100000); do
  curl -s -X "METHOD$(printf '%06d' $i)" \
    http://<rosetta-host>:<port>/network/list \
    -H "Content-Type: application/json" \
    -d '{"metadata":{}}' &
done
wait
```

Each iteration sends a request with a unique method token (`METHOD000001`, `METHOD000002`, …). The weaveworks `Instrument` middleware records a new label combination for each, growing the Prometheus registry's in-memory time series without bound. Monitor the Rosetta process RSS (`/proc/<pid>/status`) — it will grow continuously until OOM termination, at which point all pending transaction history responses are dropped.