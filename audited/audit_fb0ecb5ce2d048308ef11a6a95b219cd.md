### Title
Unauthenticated `/metrics` Endpoint Exposes Full Prometheus Histogram Data Including Per-Route Request Size Distributions

### Summary
The `/metrics` endpoint is registered on the same public port as the Rosetta API with no authentication, IP restriction, or access control of any kind. Any unprivileged external user can issue a plain `GET /metrics` and receive the full Prometheus exposition, including `hiero_mirror_rosetta_request_bytes` histogram bucket counts broken down by `method` and `route` labels, directly revealing which endpoints receive large payloads and the distribution of request body sizes across all bucket boundaries.

### Finding Description
In `rosetta/app/middleware/metrics.go` lines 64–73, `Routes()` registers the `/metrics` path using the default `promhttp.Handler()` with no wrapper, guard, or middleware:

```go
func (c *metricsController) Routes() server.Routes {
    return server.Routes{
        {
            "metrics",
            "GET",
            metricsPath,
            promhttp.Handler().ServeHTTP,  // bare handler, no auth
        },
    }
}
```

In `rosetta/main.go` lines 217–219, the middleware chain applied to the entire server is:

```go
metricsMiddleware := middleware.MetricsMiddleware(router)
tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

None of these layers add authentication. The only special treatment of `/metrics` is in `rosetta/app/middleware/trace.go` line 19:

```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

This `internalPaths` map is used exclusively to downgrade the log level to `debug` (lines 55–58 of `trace.go`). It does **not** block, redirect, or challenge requests — it is purely a logging concern. There is no IP allowlist, no bearer token check, no network-level separation (the metrics port is the same `rosettaConfig.Port` as the API).

The histograms registered in `init()` (lines 46–52 of `metrics.go`) use `prometheus.DefaultRegisterer`, so `promhttp.Handler()` (which reads from `prometheus.DefaultGatherer`) exposes all four metrics — including `hiero_mirror_rosetta_request_bytes` with `sizeBuckets = []float64{512, 1024, 10240, 25600, 51200}` — labelled by `{method, route}`.

**Exploit flow:**
1. Attacker sends `GET /metrics` to the public Rosetta port with no credentials.
2. Server returns HTTP 200 with `Content-Type: text/plain; version=0.0.4`.
3. Response contains lines such as:
   ```
   hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="51200"} 47
   hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="+Inf"} 47
   hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/block/transaction",le="1024"} 312
   ```
4. By subtracting adjacent bucket counts the attacker reconstructs the exact histogram of request body sizes per route, identifying which endpoints regularly receive payloads near or above the 25 KB / 51.2 KB buckets.

### Impact Explanation
The exposed data enables an attacker to:
- Enumerate all active API routes and their HTTP methods (label cardinality reveals the full route map).
- Determine which endpoints accept large request bodies (construction endpoints, block endpoints) and craft targeted oversized-payload or resource-exhaustion attacks.
- Observe `hiero_mirror_rosetta_request_inflight` gauge values to time attacks during peak load.
- Correlate `hiero_mirror_rosetta_request_duration` percentiles with `request_bytes` to identify slow, large-payload paths most susceptible to amplification.

This is an information-disclosure vulnerability that materially assists targeted abuse; it requires zero privileges and zero prior knowledge of the API surface.

### Likelihood Explanation
Exploitation requires only a single unauthenticated HTTP GET to a known path (`/metrics`) on the public port. No credentials, tokens, or special network position are needed. The path is standard and well-known for any Prometheus-instrumented Go service. Any attacker who can reach the service port — including internet-facing deployments — can exploit this immediately and repeatedly.

### Recommendation
1. **Separate the metrics port**: Serve `promhttp.Handler()` on a dedicated, non-public port (e.g., `:9090`) bound only to `localhost` or an internal network interface, completely separate from `rosettaConfig.Port`.
2. **If a single port is required**: Add an authentication middleware (e.g., bearer token or mutual TLS) specifically for the `/metrics` route before `promhttp.Handler()`.
3. **Remove the misleading `internalPaths` guard**: The current `internalPaths` map creates a false impression of access restriction; either remove it or replace it with actual access control.

### Proof of Concept
```bash
# No credentials required. Replace <host> and <port> with the Rosetta server address.
curl -s http://<host>:<port>/metrics | grep hiero_mirror_rosetta_request_bytes_bucket

# Expected output (example):
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="512"} 0
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="1024"} 3
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="10240"} 41
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="25600"} 47
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="51200"} 47
# hiero_mirror_rosetta_request_bytes_bucket{application="rosetta",method="POST",route="/construction/payloads",le="+Inf"} 47
# hiero_mirror_rosetta_request_bytes_sum{...} 284672
# hiero_mirror_rosetta_request_bytes_count{...} 47
```

From this output an attacker directly reads that 44 of 47 requests to `/construction/payloads` had bodies between 1 KB and 10 KB, confirming it as a high-volume, medium-payload endpoint suitable for targeted abuse.