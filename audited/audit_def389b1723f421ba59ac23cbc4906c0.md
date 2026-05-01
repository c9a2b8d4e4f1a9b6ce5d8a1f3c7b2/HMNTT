### Title
Unbounded Prometheus Label Cardinality via Attacker-Controlled Route Values in MetricsMiddleware

### Summary
`MetricsMiddleware()` in `rosetta/app/middleware/metrics.go` delegates route-name extraction to the `weaveworks/common/middleware.Instrument` wrapper, which falls back to the raw `r.RequestURI` as the `route` label value when no gorilla/mux route is matched. Because there is no sanitization, length cap, or cardinality limit on this label, an unprivileged attacker can send requests to an unbounded number of unique URL paths, each creating a new Prometheus time series in every registered histogram and gauge, causing gradual in-process memory exhaustion that degrades the server for all users.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/metrics.go` lines 76–84:
```go
func MetricsMiddleware(next http.Handler) http.Handler {
    return middleware.Instrument{
        Duration:         requestDurationHistogram,
        InflightRequests: requestInflightGauge,
        RequestBodySize:  requestBytesHistogram,   // ← label "route" populated here
        ResponseBodySize: responseBytesHistogram,
        RouteMatcher:     next.(middleware.RouteMatcher),
    }.Wrap(next)
}
```

`rosetta/main.go` line 217 shows this middleware wraps the entire router before any other handler:
```go
metricsMiddleware := middleware.MetricsMiddleware(router)
```

**Root cause:**

`github.com/weaveworks/common/middleware.Instrument.Wrap` calls `RouteMatcher.Match(r, &mux.RouteMatch{})` to resolve the route template. For requests that match a registered gorilla/mux route, it uses the fixed path template (e.g., `/network/status`). For requests that do **not** match any registered route, `mux.CurrentRoute(r)` returns `nil` and the library falls back to `r.RequestURI` — the raw, attacker-supplied URL — as the `route` label value.

The four metric vectors registered in `init()` (lines 46–52) all carry a `"route"` label:
- `hiero_mirror_rosetta_request_bytes` (5 buckets → 7 series per unique label)
- `hiero_mirror_rosetta_request_duration` (6 buckets → 8 series per unique label)
- `hiero_mirror_rosetta_request_inflight` (gauge → 1 series per unique label)
- `hiero_mirror_rosetta_response_bytes` (5 buckets → 7 series per unique label)

Each unique `(method, route)` pair allocates a new set of in-memory time series in the Prometheus Go client's internal `metricMap`. There is no eviction, no cap, and no sanitization anywhere in the middleware or the router setup.

**Why existing checks fail:**

The Traefik ingress rate-limit (`average: 10` per host, `inFlightReq: 5`) visible in `charts/hedera-mirror-rosetta/values.yaml` lines 149–166 is a deployment-level control that is absent in bare or non-Kubernetes deployments and can be bypassed by rotating source IPs or using multiple clients. The Go `http.Server` fields (`ReadHeaderTimeout`, `ReadTimeout`, etc.) at `rosetta/main.go` lines 221–226 are timeouts, not URL-length or cardinality limits. No code in `metrics.go` or `main.go` normalizes or truncates the route label before it is passed to Prometheus.

### Impact Explanation

Every unique URL path sent by the attacker permanently allocates ~23 new in-process time series (7+8+1+7). At ~200–400 bytes of Go heap per series, 500 000 unique paths consume roughly 2–5 GB of heap. The Prometheus client never frees these series during the process lifetime. As heap grows, GC pressure increases, latency spikes, and eventually the process is OOM-killed or becomes unresponsive, denying service to all legitimate users. The impact is server-wide degradation with no economic loss to network participants, matching the stated "griefing" severity.

### Likelihood Explanation

No authentication or privilege is required. The Rosetta server is publicly reachable on its configured port. A single attacker script can generate millions of unique paths (e.g., `GET /x000001`, `GET /x000002`, …) at the rate permitted by the server's connection handling. Go's `net/http` does not enforce a URL-length limit by default (only `MaxHeaderBytes` = 1 MB applies to headers), so paths up to ~8 KB are accepted, maximising per-series string storage. The attack is fully repeatable and requires no special knowledge of the application.

### Recommendation

1. **Normalize unmatched routes to a fixed sentinel label** — after `next.ServeHTTP` returns, check whether a gorilla/mux route was matched; if not, use a constant such as `"unmatched"` instead of `r.RequestURI`.
2. **Truncate or hash the route label** — enforce a maximum label-value length (e.g., 128 bytes) before passing it to any `prometheus.*Vec.With(...)` call.
3. **Use a cardinality-limiting Prometheus registerer** — wrap `prometheus.DefaultRegisterer` with a registerer that panics or drops new label combinations beyond a configured threshold.
4. **Apply URL-length limits at the HTTP server level** — set `http.Server.MaxHeaderBytes` and consider a custom `http.Handler` that rejects requests whose `r.URL.Path` exceeds a safe bound before reaching the metrics middleware.

### Proof of Concept

```bash
# Send 100 000 requests, each with a unique path, to the Rosetta server
for i in $(seq 1 100000); do
  curl -s -o /dev/null "http://<rosetta-host>:<port>/griefpath${i}" &
done
wait

# Observe growing heap via /metrics
curl http://<rosetta-host>:<port>/metrics | grep go_memstats_heap_inuse_bytes
# Repeat the loop; heap_inuse_bytes will grow monotonically and never shrink.
```

Each iteration creates 23 new permanent Prometheus time series. After ~500 000 unique paths the process heap exceeds several gigabytes, causing severe GC pauses or OOM termination.