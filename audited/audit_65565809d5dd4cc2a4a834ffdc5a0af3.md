### Title
Trailing-Slash Path Bypass in `TracingMiddleware` Causes Health-Check Requests to Log at `Info` Instead of `Debug`

### Summary
`TracingMiddleware` performs an exact-string map lookup against `internalPaths` using `request.URL.RequestURI()`. Because the map contains only the literal strings `/health/liveness`, `/health/readiness`, and `/metrics`, a request to `/health/liveness/` (trailing slash) produces a key not present in the map and is logged at `log.Info` instead of `log.Debug`. At high request volume this inflates the Info-level log stream and can mask genuine partition-detection signals. The fragment variant (`#fragment`) is **not** exploitable: Go's `url.ParseRequestURI` rejects request-URIs containing `#` with a 400, so those requests never reach `TracingMiddleware`.

### Finding Description
**Exact location:** `rosetta/app/middleware/trace.go`, lines 47 and 55.

```
path := request.URL.RequestURI()          // line 47 – raw URI, no normalization
...
if internalPaths[path] {                  // line 55 – exact-string map lookup
    log.Debug(message)
} else {
    log.Info(message)
}
```

`internalPaths` is declared at line 19:

```
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

where `livenessPath = "/health/liveness"` (health.go line 20) and `readinessPath = "/health/readiness"` (health.go line 21).

`RequestURI()` returns the raw, un-normalized request URI verbatim. A request to `/health/liveness/` yields the string `"/health/liveness/"`, which is absent from the map, so `internalPaths[path]` evaluates to `false` and the request is logged at `Info`. The failed assumption is that health-check clients will always use the exact registered path with no suffix variation.

The router (rosetta-sdk-go, backed by gorilla/mux without `StrictSlash`) returns a 404 for `/health/liveness/`, but the response still flows through `TracingMiddleware` and is logged at `Info` before the 404 is written.

### Impact Explanation
An attacker who can reach the health endpoint (common in load-balancer-facing deployments) can generate a sustained stream of `Info`-level log entries that are indistinguishable from legitimate API traffic in the log pipeline. If the log pipeline has a throughput ceiling (rate-limiting, disk I/O, or a remote sink), this flood can delay or drop `Info`-level messages that carry real partition-detection signals (e.g., `/network/status` failures logged by `checkNetworkStatus`), causing operators to miss an active network partition.

### Likelihood Explanation
The health endpoint is frequently exposed to load balancers and, in misconfigured deployments, to the public internet. No authentication is required. The attacker needs only the ability to send HTTP GET requests at volume — a trivial capability. The trailing-slash variant is a well-known path-normalization trick that automated scanners already probe. Repeatability is unlimited.

### Recommendation
Normalize the path before the map lookup. Strip trailing slashes and discard any query string when classifying internal paths:

```go
rawPath := request.URL.Path          // already decoded, no query/fragment
cleanPath := strings.TrimRight(rawPath, "/")
if internalPaths[cleanPath] {
    log.Debug(message)
} else {
    log.Info(message)
}
```

Alternatively, extend `internalPaths` to include the trailing-slash variants, or use a prefix/exact-match helper that normalizes before comparing.

### Proof of Concept
```bash
# Single request – observe Info-level log entry instead of Debug
curl -v http://<rosetta-host>:<port>/health/liveness/

# High-volume flood to saturate log pipeline
ab -n 100000 -c 50 http://<rosetta-host>:<port>/health/liveness/
```

Expected log output (Info instead of Debug):
```
level=info msg="<ip> GET /health/liveness/ (404) in 123µs"
```

Compare with the expected suppressed output for the canonical path:
```
level=debug msg="<ip> GET /health/liveness (200) in 98µs"
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L19-19)
```go
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
```

**File:** rosetta/app/middleware/trace.go (L47-59)
```go
		path := request.URL.RequestURI()
		tracingResponseWriter := newTracingResponseWriter(responseWriter)

		inner.ServeHTTP(tracingResponseWriter, request)

		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
```

**File:** rosetta/app/middleware/health.go (L19-22)
```go
const (
	livenessPath  = "/health/liveness"
	readinessPath = "/health/readiness"
)
```
