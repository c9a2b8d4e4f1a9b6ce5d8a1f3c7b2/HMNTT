### Title
Query-String Bypass of `internalPaths` Debug Suppression Enables Unauthenticated Info-Level Log Flooding in `TracingMiddleware`

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` uses `request.URL.RequestURI()` to capture the request path, which includes the raw query string. The `internalPaths` map is keyed on bare paths (e.g., `/health/liveness`) with no query component. Any request to `/health/liveness?<anything>` produces a key that misses the map, causing the entry to be emitted at `log.Info` instead of `log.Debug`. Because the health endpoint is unauthenticated and rate-unlimited, an external attacker can trivially flood the info-level log with arbitrarily many entries, burying legitimate transaction-related log lines.

### Finding Description
**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 47 and 55:

```go
// line 47 — captures full URI including query string
path := request.URL.RequestURI()

// line 55 — map keys are bare paths; query string makes lookup miss
if internalPaths[path] {
    log.Debug(message)   // never reached for ?-suffixed requests
} else {
    log.Info(message)    // always reached
}
```

`internalPaths` (line 19) is:
```go
var internalPaths = map[string]bool{
    livenessPath:  true,   // "/health/liveness"
    metricsPath:   true,   // "/metrics"
    readinessPath: true,   // "/health/readiness"
}
```

Go's `URL.RequestURI()` is documented to return `encoded path?query`. For a request `GET /health/liveness?x=abc`, it returns `/health/liveness?x=abc`. The map lookup `internalPaths["/health/liveness?x=abc"]` returns `false`, so `log.Info` fires.

**Root cause / failed assumption:** The developer assumed `request.URL.RequestURI()` returns only the path segment. It does not — it returns path + raw query. The suppression check therefore only works for requests with no query string.

**Compounding factor:** `getClientIpAddress` (lines 63–74) trusts the attacker-controlled `X-Real-IP` and `X-Forwarded-For` headers before falling back to `RemoteAddr`. An attacker can forge arbitrary source IPs in every log entry, making the flood appear to originate from many different hosts and defeating IP-based filtering during forensic review.

### Impact Explanation
An attacker who floods the info-level log with thousands of entries of the form:
```
<spoofed-ip> GET /health/liveness?x=<random> (200) in 1ms
```
makes it practically impossible to reconstruct the chronological order of legitimate Rosetta API calls (e.g., `/construction/submit`, `/block/transaction`) from the log stream. Log-based audit trails and incident-response timelines are rendered unreliable. If the deployment uses a log-size cap or rotation policy, legitimate entries can be evicted entirely. This maps directly to the stated scope: *reorganizing/obscuring transaction history* at the observability layer without any direct on-chain action.

### Likelihood Explanation
- **No authentication required** on `/health/liveness` — it is a public health probe by design.
- **No rate limiting** is applied anywhere in the middleware stack shown.
- **No query-string stripping** occurs before the path is captured.
- A single attacker with a modest HTTP flood tool (e.g., `wrk`, `ab`, `curl` in a loop) can sustain thousands of requests per second. The query string can be randomized trivially (`?x=$(uuidgen)`), defeating any simple deduplication.
- The `X-Forwarded-For` spoofing requires zero privilege and makes IP-based blocking ineffective.

### Recommendation
Replace `request.URL.RequestURI()` with `request.URL.Path` (which contains only the decoded path, no query string) for the purpose of the `internalPaths` lookup and log message:

```go
// Before (vulnerable)
path := request.URL.RequestURI()

// After (fixed)
path := request.URL.Path
```

If the full URI (including query) is still desired in the log message for non-internal paths, capture both separately:

```go
path    := request.URL.Path          // used for internalPaths lookup
fullURI := request.URL.RequestURI()  // used only in the log message
```

Additionally, stop trusting `X-Real-IP` / `X-Forwarded-For` unless the service is deployed behind a known, trusted reverse proxy, or validate that the header originates from a trusted CIDR.

### Proof of Concept
```bash
# Flood the info-level log; no credentials needed
for i in $(seq 1 10000); do
  curl -s -o /dev/null \
    -H "X-Real-IP: 10.$(( RANDOM % 256 )).$(( RANDOM % 256 )).1" \
    "http://<rosetta-host>:<port>/health/liveness?x=$(cat /proc/sys/kernel/random/uuid)" &
done
wait
```

Each request produces a line such as:
```
level=info msg="10.x.x.1 GET /health/liveness?x=<uuid> (200) in 312µs"
```
at `log.Info` level, indistinguishable in severity from legitimate Rosetta API transaction calls, burying them in the log stream.