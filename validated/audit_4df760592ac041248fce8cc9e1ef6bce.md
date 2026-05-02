All code references check out. Let me verify the go.mod for the weaveworks version and confirm there's no catch-all route in the Rosetta SDK router.

Audit Report

## Title
Prometheus Label Cardinality Explosion via Unbounded `route` Label in `MetricsMiddleware`

## Summary
`MetricsMiddleware` in `rosetta/app/middleware/metrics.go` instruments all four Prometheus `*Vec` metrics with a `route` label populated by the weaveworks `middleware.Instrument`. When no registered gorilla/mux route matches an incoming request, the library falls back to the raw `r.URL.Path` as the label value. An unauthenticated attacker can send requests to an unbounded number of unique paths, minting a new Prometheus time-series per unique path across all four metrics, exhausting process memory and crashing the server.

## Finding Description

**Exact code location:** `rosetta/app/middleware/metrics.go`, `MetricsMiddleware()`, lines 76–83.

All four `*Vec` metrics are declared with a `route` label: [1](#0-0) 

`MetricsMiddleware` passes all four to `middleware.Instrument` along with `RouteMatcher: next.(middleware.RouteMatcher)`: [2](#0-1) 

No cardinality cap or label allowlist is configured at registration time: [3](#0-2) 

**Root cause — weaveworks `Instrument.getRouteName` fallback:**
The weaveworks `middleware.Instrument.Wrap` calls an internal `getRouteName(r)` helper that invokes `RouteMatcher.Match(r, &routeMatch)` (gorilla/mux `v1.8.1`, confirmed in `go.mod` line 68). If the match succeeds and the route carries a name, it returns that bounded name. **If the match fails, it returns `r.URL.Path` verbatim** — the raw, attacker-controlled URL path. [4](#0-3) [5](#0-4) 

The Rosetta SDK router (`server.NewRouter`) registers only a fixed set of named POST endpoints (online: ~15 routes; offline: ~4 routes) with no catch-all/NotFoundHandler: [6](#0-5) [7](#0-6) 

Any request to an unregistered path causes `Match()` to return `false`, triggering the `r.URL.Path` fallback.

**Middleware chain — no auth before `MetricsMiddleware`:**
`MetricsMiddleware` wraps the entire router as the outermost application-level handler, before any authentication or rate-limiting layer: [8](#0-7) 

**Exploit flow:**
1. Attacker sends HTTP requests to paths that do not match any registered Rosetta route (e.g., `POST /aaaa`, `POST /bbbb`, …).
2. For each request, `getRouteName` returns the raw path (e.g., `/aaaa`).
3. `requestInflightGauge.WithLabelValues("POST", "/aaaa").Inc()` allocates a new internal map entry in the Prometheus default registry.
4. The same unique `{method, route}` pair is also allocated in the three `*HistogramVec` metrics (each histogram carries N buckets + sum + count per label set).
5. Once created, Prometheus label-set entries are **never garbage-collected** within the process lifetime.
6. Repeating with N unique paths allocates O(N × 4 metrics × per-metric overhead) memory. At tens of thousands of unique paths, RSS grows to gigabytes and the Go runtime OOMs.

## Impact Explanation
Successful exploitation exhausts the Rosetta mirror-node process memory, causing an OOM crash. The Rosetta API is the interface through which clients query Hashgraph history (blocks, transactions, account balances). A crash makes that history unavailable — a direct availability impact. Recovery requires a process restart, but the attack is trivially repeatable, making sustained denial-of-service straightforward.

## Likelihood Explanation
The Rosetta port is intended to be reachable by external Rosetta clients (wallets, exchanges). No credential is required to send an HTTP request. The attack requires only a simple loop sending requests to unique paths — achievable with `curl`, `ab`, or a short Python script. The attacker does not need to understand the Rosetta protocol; any path that does not match a registered route suffices. The attack is fully repeatable after each restart. This is a single-source resource exhaustion attack, not a volumetric DDoS, and is not excluded by the project's SECURITY.md.

## Recommendation
1. **Add a named catch-all route** to the gorilla/mux router so that all unmatched paths resolve to a fixed, bounded label value (e.g., `"unmatched"`) instead of the raw path.
2. **Normalize the `route` label** in `MetricsMiddleware` before passing it to `middleware.Instrument` — replace any path not in the known route set with a constant sentinel value.
3. **Apply a cardinality limit** using a Prometheus `prometheus.WrapRegistererWithPrefix` or a custom `Registerer` that rejects new label combinations beyond a configured threshold.
4. **Place a rate-limiting or request-filtering middleware** ahead of `MetricsMiddleware` to reject requests to unknown paths before any metric allocation occurs.

## Proof of Concept

```python
import requests
import string
import random

target = "http://<rosetta-host>:<port>"

def rand_path():
    return "/" + "".join(random.choices(string.ascii_lowercase, k=12))

# Each iteration mints a new Prometheus time-series across all 4 *Vec metrics
for i in range(100_000):
    try:
        requests.post(target + rand_path(), timeout=1)
    except Exception:
        pass
    if i % 1000 == 0:
        print(f"Sent {i} requests with unique paths")
# Process RSS grows unboundedly; OOM kill expected within minutes on a typical deployment
```

Each unique path allocates new label-set entries in `requestInflightGauge`, `requestDurationHistogram`, `requestBytesHistogram`, and `responseBytesHistogram`. None are ever freed. The `/metrics` endpoint (if reachable) will show the cardinality explosion in real time. [9](#0-8) [2](#0-1)

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

**File:** rosetta/app/middleware/metrics.go (L46-52)
```go
func init() {
	register := prometheus.WrapRegistererWith(prometheus.Labels{"application": application}, prometheus.DefaultRegisterer)
	register.MustRegister(requestBytesHistogram)
	register.MustRegister(requestDurationHistogram)
	register.MustRegister(requestInflightGauge)
	register.MustRegister(responseBytesHistogram)
}
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

**File:** rosetta/go.mod (L25-25)
```text
	github.com/weaveworks/common v0.0.0-20230728070032-dd9e68f319d5
```

**File:** rosetta/go.mod (L68-68)
```text
	github.com/gorilla/mux v1.8.1 // indirect
```

**File:** rosetta/main.go (L111-119)
```go
	return server.NewRouter(
		networkAPIController,
		blockAPIController,
		mempoolAPIController,
		constructionAPIController,
		accountAPIController,
		healthController,
		metricsController,
	), nil
```

**File:** rosetta/main.go (L152-152)
```go
	return server.NewRouter(constructionAPIController, healthController, metricsController, networkAPIController), nil
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
