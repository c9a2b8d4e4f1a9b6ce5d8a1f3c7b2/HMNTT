### Title
Unbounded Prometheus Label Cardinality via Arbitrary HTTP Methods in `MetricsMiddleware` Leads to Memory Exhaustion (OOM)

### Summary
`MetricsMiddleware()` in `rosetta/app/middleware/metrics.go` delegates instrumentation to `weaveworks/common/middleware.Instrument`, which uses the raw `r.Method` value directly as the `method` label in all four Prometheus metric vectors (`requestInflightGauge`, `requestDurationHistogram`, `requestBytesHistogram`, `responseBytesHistogram`). Go's `net/http` server accepts any valid HTTP token as a method without restriction, so an unauthenticated attacker can send requests with an unbounded number of unique custom method strings, creating a new persistent Prometheus label series per unique method across all four vectors. This causes unbounded heap growth and eventual OOM crash of the rosetta node.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/metrics.go`, lines 34–37 and 76–83:

```go
requestInflightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
    Name: "hiero_mirror_rosetta_request_inflight",
    Help: "Current number of inflight HTTP requests.",
}, []string{"method", "route"})
```

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

**Root cause:** `weaveworks/common/middleware.Instrument.Wrap()` (version `v0.0.0-20230728070032-dd9e68f319d5`, used per `rosetta/go.mod` line 25) calls `requestInflightGauge.With(prometheus.Labels{"method": r.Method, "route": route}).Inc()` at request entry and `.Dec()` at exit. The `r.Method` value is taken verbatim from the HTTP request with no allowlisting or normalization. Prometheus `GaugeVec`/`HistogramVec` store one time series per unique label combination in an in-memory map that is **never garbage-collected** during the process lifetime.

**Failed assumption:** The code assumes the `method` label has bounded cardinality (e.g., GET, POST, PUT, DELETE). Go's `net/http` server does not enforce this — it accepts any RFC 7230 token as a method and populates `r.Method` with the raw string.

**Exploit flow:**
1. Attacker sends HTTP requests with unique method strings: `M1`, `M2`, `M3`, ..., `Mn`.
2. Each request passes through `corsMiddleware → tracingMiddleware → MetricsMiddleware` (see `rosetta/main.go` lines 217–219) before reaching the router.
3. `Instrument.Wrap()` calls `.With({"method": "M1", "route": ...}).Inc()` — creating a new entry in the internal `sync.Map` of all four metric vectors.
4. After the request completes, `.Dec()` is called but the label series **remains allocated** in the Prometheus registry.
5. After N unique methods, N persistent series exist across all four vectors. Each `HistogramVec` series allocates bucket arrays (5 buckets for size histograms, 6 for duration). Total series per unique method ≈ 23.
6. Heap grows without bound → OOM → process crash.

**No method validation exists** in the rosetta Go codebase: `grep` for `MethodNotAllowed`, `AllowedMethods`, `r.Method` in `rosetta/**/*.go` returns zero results.

### Impact Explanation

The rosetta process crashes (OOM kill) when heap is exhausted. This takes down the Rosetta API node entirely, preventing all blockchain data access and construction operations. The severity matches the stated scope: shutdown of a processing node without brute force. Because all four metric vectors are affected simultaneously, memory growth is amplified ~23× per unique method string. A single attacker with a script can exhaust gigabytes of heap in minutes.

### Likelihood Explanation

No authentication is required to reach `MetricsMiddleware` — it wraps the outermost handler before any routing or auth logic (`rosetta/main.go` lines 217–219). The only potential mitigations are the optional Traefik Helm chart settings (`rateLimit: average: 10`, `inFlightReq: amount: 5` in `charts/hedera-mirror-rosetta/values.yaml` lines 152–160), but these are:
- Not enforced at the application level (absent when deployed without Traefik)
- Insufficient even when present: rate-limiting to 10 req/s still allows 10 new permanent label series per second; over hours this exhausts memory

The attack is trivially scriptable with `curl` or any HTTP client that allows custom methods.

### Recommendation

1. **Normalize the method label** before passing to Prometheus: allowlist standard HTTP methods (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `CONNECT`, `TRACE`) and replace any unrecognized method with a fixed string (e.g., `"unknown"`) before constructing the `Instrument` struct or by wrapping the handler to rewrite `r.Method`.
2. **Apply method validation at the HTTP server level** using a middleware that rejects (405) any request whose method is not in the allowed set, placed before `MetricsMiddleware` in the chain.
3. **Do not rely solely on infrastructure-level rate limiting** (Traefik) as the sole defense against label cardinality attacks.

### Proof of Concept

```bash
# Send 100,000 requests with unique HTTP methods to the rosetta node
for i in $(seq 1 100000); do
  curl -s -X "METHOD${i}" http://<rosetta-host>:<port>/network/list \
    -H "Content-Type: application/json" \
    -d '{}' &
done
wait
# Monitor rosetta process memory: watch -n1 'ps aux | grep rosetta'
# Process will OOM-crash as heap grows unboundedly
```

Each iteration creates a new permanent `{method="METHODn", route=...}` label series in all four Prometheus metric vectors. No authentication, no special privileges, no brute force required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rosetta/app/middleware/metrics.go (L34-37)
```go
	requestInflightGauge = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "hiero_mirror_rosetta_request_inflight",
		Help: "Current number of inflight HTTP requests.",
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

**File:** rosetta/go.mod (L25-25)
```text
	github.com/weaveworks/common v0.0.0-20230728070032-dd9e68f319d5
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-160)
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
```
