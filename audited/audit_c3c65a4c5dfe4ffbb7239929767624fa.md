### Title
Histogram +Inf Bucket Saturation via Slow Requests Degrades SLO Duration Monitoring

### Summary
The `requestDurationHistogram` in `MetricsMiddleware()` defines a maximum bucket of 5 seconds, but the HTTP server's default `WriteTimeout` (10 s) and the DB `statementTimeout` (20 s) both permit requests to run well beyond that ceiling. Any unauthenticated external user can send requests to computationally expensive endpoints, causing every observation above 5 s to land in the implicit `+Inf` bucket and rendering the histogram useless for SLO alerting across all users.

### Finding Description
**Exact code location:** `rosetta/app/middleware/metrics.go`, lines 28–32 — the histogram is declared with buckets `{.1, .25, .5, 1, 2.5, 5}` seconds; 5 s is the hard ceiling.

```go
requestDurationHistogram = prometheus.NewHistogramVec(prometheus.HistogramOpts{
    Name:    "hiero_mirror_rosetta_request_duration",
    Buckets: []float64{.1, .25, .5, 1, 2.5, 5},   // max = 5 s
    ...
}, []string{"method", "route", "status_code", "ws"})
```

**Root cause — three misaligned ceilings:**

| Limit | Default value | Source |
|---|---|---|
| Histogram max bucket | **5 s** | `metrics.go:30` |
| HTTP `WriteTimeout` | **10 s** (10 000 000 000 ns) | `docs/configuration.md:667`, `main.go:226` |
| DB `statementTimeout` | **20 s** | `docs/configuration.md:662`, `db/client.go:36` |

The `weaveworks/common/middleware.Instrument` wrapper records wall-clock duration from request start to response completion. Any handler that takes between 5 s and 10 s (bounded by `WriteTimeout`) produces an observation that exceeds every defined bucket and is counted only in `+Inf`.

**Failed assumption:** the histogram author assumed all legitimate requests complete within 5 s. The server itself is configured to tolerate up to 10 s of response time and up to 20 s of DB query time, directly contradicting that assumption.

**No application-level rate limiting or per-request timeout exists in the Go middleware chain.** The chain is:

```
MetricsMiddleware → TracingMiddleware → CorsMiddleware → router
```

(`main.go:217–219`) — no throttle, no context deadline injected before the handler runs.

**Traefik-level protection is disabled by default.** `charts/hedera-mirror-rosetta/values.yaml:95` sets `global.middleware: false`; the Traefik `Middleware` CRD template (`templates/middleware.yaml:3`) gates on `and .Values.global.middleware .Values.middleware`, so the `inFlightReq` (5 concurrent/IP) and `rateLimit` (10 req/s per host) rules are never applied in a default deployment.

**Exploit flow:**
1. Attacker identifies endpoints backed by expensive DB queries (e.g. `/block`, `/account/balance` for high-volume accounts).
2. Attacker sends a sustained stream of such requests from one or more IPs (no auth required, no rate limit active by default).
3. DB queries run for 6–19 s (within the 20 s `statementTimeout`); HTTP handler completes within `WriteTimeout` (10 s).
4. Every duration observation > 5 s is recorded only in `+Inf`.
5. At scale, the `+Inf` bucket dominates; all percentile-based SLO queries (e.g. `histogram_quantile(0.99, ...)`) return `+Inf` or become statistically meaningless.

### Impact Explanation
The `hiero_mirror_rosetta_request_duration` histogram is the sole source of latency SLO data for the Rosetta API (the `RosettaApiErrors` PrometheusRule in `values.yaml:196` already uses the `_count` series; latency alerting depends on the histogram). Once `+Inf` dominates, operators lose the ability to distinguish normal load from a latency regression or an ongoing slow-query attack. Incident detection and SLO burn-rate alerts are silently broken for every user of the monitoring stack, not just the attacker's sessions.

### Likelihood Explanation
The Rosetta API is a public, unauthenticated HTTP service. No credentials, tokens, or network-level access controls are required to reach it. The default Helm chart ships with `global.middleware: false`, meaning the Traefik rate-limit and in-flight-request guards are absent in the most common deployment scenario. An attacker needs only a script that repeatedly POSTs to a slow endpoint; no exploit tooling, no chain-specific knowledge, and no economic stake is required. The attack is trivially repeatable and can be sustained indefinitely.

### Recommendation
1. **Align histogram buckets with actual server limits.** Extend buckets to at least cover `WriteTimeout`: e.g. `{.1, .25, .5, 1, 2.5, 5, 10}`.
2. **Inject a per-request context deadline** in the middleware chain (before the handler) equal to `WriteTimeout` so the DB query is cancelled and the observation is bounded.
3. **Enable Traefik middleware by default** (`global.middleware: true`) or add an equivalent in-process rate limiter/concurrency limiter to the Go middleware chain.
4. **Add a Prometheus alert** on `increase(hiero_mirror_rosetta_request_duration_bucket{le="+Inf"}[5m]) > threshold` to detect bucket saturation proactively.

### Proof of Concept
```bash
# Prerequisites: rosetta running at localhost:5700, default config (no rate limit)
# Target: /block endpoint with a block identifier that triggers a full DB scan

for i in $(seq 1 200); do
  curl -s -X POST http://localhost:5700/block \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},
         "block_identifier":{"index":1}}' &
done
wait

# After ~60 s, scrape metrics and observe:
curl -s http://localhost:5700/metrics \
  | grep 'hiero_mirror_rosetta_request_duration_bucket.*le="\+Inf"'

# Expected: +Inf bucket count >> all finite bucket counts combined,
# making histogram_quantile(0.99, ...) return +Inf in Prometheus.
```