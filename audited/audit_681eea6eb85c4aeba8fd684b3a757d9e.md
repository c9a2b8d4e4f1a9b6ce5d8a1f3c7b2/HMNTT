### Title
Unbounded Log Amplification via Unauthenticated Requests to Non-Internal Paths in `TracingMiddleware`

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally emits a `log.Info` message for every HTTP request whose path is not in the three-entry `internalPaths` map. Because the log message always includes `time.Since(start)`, every entry is globally unique, defeating any log-sink deduplication. The Rosetta Go application contains no in-process rate limiting, and the optional Traefik middleware chain that would impose one is disabled by default (`global.middleware: false`), so an unauthenticated attacker can drive log I/O and storage to grow without bound.

### Finding Description
**Exact code path:** `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61.

```go
// line 47
path := request.URL.RequestURI()          // includes full query string

// lines 52-53
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

// lines 55-59
if internalPaths[path] {
    log.Debug(message)   // only /health/liveness, /health/readiness, /metrics
} else {
    log.Info(message)    // every other path → always logged
}
```

**Root cause / failed assumption:** The middleware assumes that non-internal traffic is low-volume and that log sinks can deduplicate repeated messages. Both assumptions fail:

1. `time.Since(start)` is a nanosecond-resolution duration that differs on every call, making every log line unique even for identical paths.
2. `request.URL.RequestURI()` includes the raw query string, so `/?x=1`, `/?x=2`, … are treated as distinct paths, each producing a distinct log line.
3. There is no rate limiter, counter, or sampling gate anywhere in the Rosetta Go codebase (confirmed: zero matches for `rateLimit`/`RateLimit` in `rosetta/**/*.go`).

**Why the only apparent guard is insufficient:** `charts/hedera-mirror-rosetta/values.yaml` defines a Traefik middleware chain that includes `rateLimit: average: 10` (line 157–160), but this chain is gated on `{{ if and .Values.global.middleware .Values.middleware }}` (middleware.yaml line 3). The chart default is `global.middleware: false` (values.yaml line 95), so the rate-limiting middleware is **off by default**. Even when enabled, the criterion is `requestHost: true` (per destination host, not per source IP), so an attacker hitting the service directly or through multiple virtual hosts bypasses it entirely.

### Impact Explanation
Each HTTP request to any non-internal path costs one `log.Info` write. With no in-process throttle, an attacker sustaining, say, 5 000 req/s (trivially achievable with a single `wrk` or `hey` instance on a LAN) produces ~5 000 log lines/s. A typical baseline of a lightly loaded Rosetta node might be tens of lines/s; 5 000 lines/s is orders of magnitude above the 30 % threshold. Log storage fills at a rate proportional to request volume × average line length (≈80–120 bytes each). Disk exhaustion or log-pipeline back-pressure can degrade or crash the node. Because the log call happens **after** `inner.ServeHTTP` (line 50), the handler itself also consumes CPU/memory for each request, compounding the resource impact.

### Likelihood Explanation
No authentication, API key, or network-level credential is required to reach the Rosetta HTTP port. The exploit requires only the ability to send TCP connections to the service port, which is the normal public-facing API port. The attack is trivially scriptable, repeatable, and requires no special knowledge of the application beyond knowing it is a Rosetta node. A single commodity machine is sufficient to exceed the 30 % threshold.

### Recommendation
1. **Add in-process rate limiting** in `TracingMiddleware` (or a dedicated middleware registered before it) using a token-bucket per source IP (e.g., `golang.org/x/time/rate`). Reject or silently drop requests that exceed the budget before the log call is reached.
2. **Truncate or sanitize `path`** before logging: cap length (e.g., 256 bytes) and strip or hash the query string to collapse high-cardinality variants into a single log-line template, enabling sink-level deduplication.
3. **Enable the Traefik middleware chain by default** (`global.middleware: true`) and change `sourceCriterion` from `requestHost` to `ipStrategy` so the limit is per source IP, not per destination host.
4. **Add log sampling** (e.g., log only 1-in-N non-error requests, or use a rate-limited logger) so that a flood of requests does not translate linearly into log I/O.

### Proof of Concept
```bash
# Prerequisites: network access to the Rosetta API port (default 5700), no credentials needed.

# 1. Establish baseline log rate (e.g., count lines/s in the log file or log sink).

# 2. Send a flood of requests with unique query strings to a non-internal path:
seq 1 100000 | xargs -P 50 -I{} \
  curl -s -o /dev/null "http://<rosetta-host>:5700/network/list?_={}"

# Each request hits TracingMiddleware; path = "/network/list?_=<N>" (unique per N).
# time.Since(start) is also unique per request.
# Result: 100 000 unique log.Info lines emitted, no deduplication possible.

# 3. Observe log storage growth and I/O rate exceed 30% above the baseline measured in step 1.
# With 50 parallel workers the throughput easily reaches thousands of req/s on a LAN.
```