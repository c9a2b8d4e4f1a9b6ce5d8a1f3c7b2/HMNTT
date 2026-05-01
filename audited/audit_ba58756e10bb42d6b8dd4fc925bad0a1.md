### Title
Unbounded HTTP Method String Used as Prometheus Label Causes Memory Exhaustion DoS in MetricsMiddleware

### Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` passes `r.Method` directly to four Prometheus metric vectors as a label value without any length cap or normalization. Because the `http.Server` in `rosetta/main.go` sets no `MaxHeaderBytes` (leaving Go's 1 MB default), an attacker can craft requests with unique, arbitrarily long method strings. Each unique method string creates a new in-memory Prometheus time series, causing unbounded heap growth and eventual OOM.

### Finding Description
**Code path:**

`rosetta/main.go` lines 220–227 construct the `http.Server` with no `MaxHeaderBytes` field set, so Go's default of 1 MB applies to the entire request line (method + URL + version).

`rosetta/app/middleware/metrics.go` lines 76–84 wrap every incoming request with `middleware.Instrument` from `github.com/weaveworks/common/middleware`. That library extracts `r.Method` verbatim and passes it as the `"method"` label to all four metric vectors:

- `requestBytesHistogram` (lines 22–26) — labels `["method","route"]`
- `requestDurationHistogram` (lines 28–32) — labels `["method","route","status_code","ws"]`
- `requestInflightGauge` (lines 34–37) — labels `["method","route"]`
- `responseBytesHistogram` (lines 39–43) — labels `["method","route"]`

**Root cause:** The code assumes HTTP methods are short, well-known tokens (GET, POST, …). No validation, truncation, or allow-list check is applied before the raw method string is stored as a Prometheus label value.

**Why existing checks fail:**
- Go's 1 MB `MaxHeaderBytes` default limits a *single* method to ~1 MB but does not bound the *number* of unique methods across requests.
- `ReadHeaderTimeout` (set via config) limits connection time but does not prevent a slow stream of valid requests each carrying a distinct long method.
- The Traefik rate-limit (`average: 10`, `inFlightReq: 5`) in `charts/hedera-mirror-rosetta/values.yaml` is an optional Kubernetes deployment artifact; it is absent in bare-metal or Docker deployments and still allows 10 unique time series per second.

### Impact Explanation
Prometheus stores every unique label-value combination as a separate in-memory time series. A 1 MB method string stored across four metric vectors consumes roughly 4 MB of heap per unique request. At Go's default 1 MB header limit, 1 000 unique requests exhaust ~4 GB of heap. The process is killed by the OOM killer, taking down the Rosetta API node and halting blockchain interaction for any client relying on it. This is a non-network-based DoS (memory exhaustion) with no authentication requirement.

### Likelihood Explanation
The Rosetta API port is externally reachable by design (it serves the Coinbase Rosetta standard). Any unauthenticated HTTP client can craft a request with a custom method; no credentials, tokens, or special network position are required. The attack is trivially scriptable in a loop with a unique method per iteration and is repeatable indefinitely. Rate limiting, when present, only slows the attack rather than preventing it.

### Recommendation
1. **Normalize the method label** before recording metrics — replace any method not in the standard allow-list (`GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, `OPTIONS`, `TRACE`, `CONNECT`) with a fixed sentinel such as `"UNKNOWN"`.
2. **Set `MaxHeaderBytes`** on the `http.Server` to a small value (e.g., 8 KB) to reject oversized request lines before they reach the middleware.
3. **Add a Prometheus cardinality guard** (e.g., `prometheus.Labels` allow-list or a custom `Registerer` that rejects new label combinations beyond a threshold).

### Proof of Concept
```bash
# Generate 500 requests each with a unique ~64 KB method string
for i in $(seq 1 500); do
  METHOD=$(python3 -c "import random,string; print(''.join(random.choices(string.ascii_uppercase, k=65000)))")
  printf "${METHOD} /network/list HTTP/1.1\r\nHost: target:8080\r\nContent-Length: 0\r\n\r\n" \
    | nc target 8080 &
done
wait
# Observe heap growth via /metrics or process RSS; repeat until OOM
```

Each iteration allocates a new time series in all four Prometheus vectors keyed by the unique 64 KB method string. After enough iterations the process is OOM-killed. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```
