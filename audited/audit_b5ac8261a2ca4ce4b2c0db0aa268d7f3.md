### Title
Unsanitized Raw URI Logged in `TracingMiddleware` Enables Log Confusion via Double-Encoded Path Characters

### Summary
`TracingMiddleware()` captures the request path using `request.URL.RequestURI()`, which returns the raw, percent-encoded URI as sent by the client, and logs it directly without any normalization or decoding. An unprivileged external user can send paths containing double-encoded sequences (e.g., `%252F` representing a literal `%2F`) that are preserved verbatim in log output. Log analysis tools or SIEM rules that expect decoded or normalized paths will misclassify or fail to match these entries.

### Finding Description
**Exact code path:**
- File: `rosetta/app/middleware/trace.go`
- Function: `TracingMiddleware()`, lines 47 and 52–53

```go
// line 47
path := request.URL.RequestURI()
// ...
// lines 52–53
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

**Root cause:** `request.URL.RequestURI()` in Go's `net/http` returns the raw, unmodified request target as transmitted by the client. For a path like `/%252Fnetwork%252Flist`, Go's URL parser sets `URL.Path = "/%2Fnetwork%2Flist"` (one decode level) and `URL.RawPath = "/%252Fnetwork%252Flist"` (preserved). `RequestURI()` calls `EscapedPath()`, which returns `RawPath` when it is a valid encoding of `Path` — so `%252F` is preserved verbatim. This raw value is then passed directly into `fmt.Sprintf` and emitted to the log with no sanitization, decoding, or normalization.

**Failed assumption:** The code assumes the path value from `RequestURI()` is a normalized, decoded string suitable for logging and for the `internalPaths` map lookup at line 55. Neither is true for double-encoded input.

**Secondary effect on `internalPaths` check (line 55):** A request to `%2Fhealth%2Fliveness` (encoding of `/health/liveness`) will not match the `livenessPath` key in `internalPaths`, so it is logged at `INFO` level instead of `Debug`, polluting production logs.

### Impact Explanation
- Log entries contain raw percent-encoded sequences (e.g., `%252F`, `%252E%252E`) instead of decoded paths.
- SIEM/alerting rules matching on decoded path strings (e.g., `/admin`, `../`) silently fail to fire.
- Log aggregation pipelines that group by path create spurious distinct buckets (`%252Fadmin` vs `/admin`), breaking dashboards and anomaly detection.
- Attackers can use this to probe endpoints while evading path-based log monitoring, with zero authentication required.
- Severity is low (griefing / monitoring degradation, no direct economic damage), consistent with the stated scope.

### Likelihood Explanation
- Requires zero privileges — any HTTP client can send an arbitrary raw URI.
- Trivially repeatable with a single `curl` command.
- No rate limiting or input validation exists in the middleware itself (Traefik-level rate limiting is an optional deployment concern, not enforced in code).
- Fully deterministic: the behavior is a direct consequence of Go's URL parsing semantics and the absence of any normalization step.

### Recommendation
Replace `request.URL.RequestURI()` with a normalized form before logging. Specifically:

1. Use `request.URL.EscapedPath()` combined with explicit single-level `url.PathUnescape()` to obtain a consistently decoded path, or
2. Use `request.URL.Path` (already single-decoded by Go's parser) concatenated with the raw query string via `request.URL.RawQuery` for the log message.
3. Additionally, strip or escape ASCII control characters (especially `\r`, `\n`, `\t`) from the path before logging to prevent log injection.

Example fix:
```go
import "net/url"

path, err := url.PathUnescape(request.URL.EscapedPath())
if err != nil {
    path = request.URL.Path // fallback to Go-decoded path
}
if request.URL.RawQuery != "" {
    path = path + "?" + request.URL.RawQuery
}
// sanitize control characters
path = strings.Map(func(r rune) rune {
    if r == '\n' || r == '\r' { return ' ' }
    return r
}, path)
```

### Proof of Concept
```bash
# Send a request with a double-encoded path
curl -v "http://<rosetta-host>:<port>/%252Fnetwork%252Flist"

# Observe the log output — entry will contain the raw encoded path:
# INFO: <ip> GET /%252Fnetwork%252Flist (404) in Xms

# A SIEM rule matching on "/network/list" will NOT fire.
# A rule matching on "/../" traversal patterns encoded as %252E%252E%252F also will NOT fire:
curl -v "http://<rosetta-host>:<port>/%252E%252E%252Fadmin"
# Log: INFO: <ip> GET /%252E%252E%252Fadmin (404) in Xms
# Path-traversal detection rules expecting decoded "../admin" are bypassed in log analysis.
```