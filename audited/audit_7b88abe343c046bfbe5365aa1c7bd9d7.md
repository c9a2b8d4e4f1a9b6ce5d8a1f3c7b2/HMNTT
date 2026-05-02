### Title
Unauthenticated Prometheus Metrics Endpoint Exposed on Public API Port

### Summary
The `/metrics` endpoint in `rosetta/app/middleware/metrics.go` is registered on the same public-facing port as all Rosetta API endpoints with no authentication, IP restriction, or access control of any kind. Any unprivileged external user can issue a single unauthenticated `GET /metrics` request and receive the full Prometheus text-format output, including all histogram bucket definitions and live operational counters. The only "special" treatment for this path is that access is logged at `DEBUG` level instead of `INFO`, which provides no security benefit.

### Finding Description
**Exact code path:**

In `rosetta/app/middleware/metrics.go` lines 64–73, `Routes()` registers the handler:

```go
func (c *metricsController) Routes() server.Routes {
    return server.Routes{
        {
            "metrics",
            "GET",
            metricsPath,          // "/metrics"
            promhttp.Handler().ServeHTTP,  // bare Prometheus handler, no auth wrapper
        },
    }
}
```

`promhttp.Handler()` is the default Prometheus HTTP handler with no authentication options configured.

In `rosetta/main.go` lines 111–119 and 152, `metricsController` is passed directly into `server.NewRouter(...)` alongside all public API controllers, binding it to the same `rosettaConfig.Port`.

The middleware chain applied in `main.go` lines 217–219 is:
```
MetricsMiddleware → TracingMiddleware → CorsMiddleware
```
None of these layers enforce authentication or restrict access to `/metrics`.

In `rosetta/app/middleware/trace.go` line 19, `metricsPath` appears in `internalPaths`:
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```
This map is used **only** to select the log level (line 55–59): requests to internal paths are logged at `DEBUG` instead of `INFO`. It provides zero access control.

**Root cause:** The failed assumption is that `internalPaths` provides any form of access restriction. It does not. The `/metrics` route is fully reachable by any client that can reach the server's port.

**What is exposed:** The full Prometheus text output includes:
- All registered histogram metric families with their bucket boundaries (`le` labels): `sizeBuckets = {512, 1024, 10240, 25600, 51200}` bytes and duration buckets `{0.1, 0.25, 0.5, 1, 2.5, 5}` seconds.
- Live counters: per-route request counts, error rates, inflight request counts, request/response byte distributions, and latency distributions — all labeled by `method` and `route`.
- Go runtime metrics and `promhttp` internal counters registered on `prometheus.DefaultRegistry`.

### Impact Explanation
An external attacker with no credentials can:
1. Map all active API routes and their traffic volumes (reconnaissance).
2. Observe error rates and latency percentiles to identify degraded states or SLA breaches.
3. Correlate inflight request counts with load patterns to time attacks.
4. Confirm which histogram bucket thresholds operators have configured, revealing performance SLA targets.

Severity: **Medium** — pure information disclosure with no direct code execution or data exfiltration, but it provides significant reconnaissance value and violates the principle of least privilege for operational telemetry.

### Likelihood Explanation
Exploitation requires only network access to the server's port and a single HTTP GET request — no credentials, no special tooling, no prior knowledge beyond the well-known `/metrics` path. This is trivially repeatable and automatable. Any internet-facing deployment is immediately affected.

### Recommendation
1. **Separate port:** Serve `/metrics` on a dedicated internal-only port (e.g., a second `http.Server` bound to `localhost` or a private network interface) rather than the public API port.
2. **Authentication middleware:** If a separate port is not feasible, wrap the handler with token-based or mTLS authentication before registering it:
   ```go
   promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{}).ServeHTTP
   // wrapped with an auth-checking http.Handler
   ```
3. **Network-level restriction:** Use firewall rules or Kubernetes `NetworkPolicy` to restrict access to the metrics port to only the Prometheus scraper's IP range.

### Proof of Concept
**Preconditions:** Network access to the Rosetta server's configured port (default behavior, no credentials needed).

**Trigger:**
```bash
curl -s http://<rosetta-host>:<port>/metrics
```

**Result:** HTTP 200 with `Content-Type: text/plain; version=0.0.4` and full Prometheus exposition including:
```
# HELP hiero_mirror_rosetta_request_duration Time (in seconds) spent serving HTTP requests.
# TYPE hiero_mirror_rosetta_request_duration histogram
hiero_mirror_rosetta_request_duration_bucket{...,le="0.1"} <count>
hiero_mirror_rosetta_request_duration_bucket{...,le="0.25"} <count>
...
# HELP hiero_mirror_rosetta_request_bytes Size (in bytes) of messages received in the request.
hiero_mirror_rosetta_request_bytes_bucket{...,le="512"} <count>
hiero_mirror_rosetta_request_bytes_bucket{...,le="1024"} <count>
...
```
All bucket boundaries, live counters, and per-route labels are returned to the unauthenticated caller.