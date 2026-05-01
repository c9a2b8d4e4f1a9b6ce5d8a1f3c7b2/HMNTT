### Title
Log Inflation via Unbounded Query String Inclusion in `TracingMiddleware`

### Summary
`TracingMiddleware` captures the full request URI — including the raw, unbounded query string — via `request.URL.RequestURI()` and writes it verbatim into every `Info`-level log entry. An unprivileged external attacker can send a high volume of requests each carrying a unique query string, producing a unique log line per request that defeats log deduplication and inflates log storage costs with no authentication or privilege required.

### Finding Description
**Exact code location:** `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 47 and 52–58.

```go
// line 47
path := request.URL.RequestURI()          // includes raw query string

// lines 52–53
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)  // path logged verbatim

// lines 55–59
if internalPaths[path] {                  // exact-match on full URI incl. query string
    log.Debug(message)
} else {
    log.Info(message)                     // all other paths → Info
}
```

**Root cause:** `net/url.URL.RequestURI()` returns the path **plus** the raw query string (e.g., `/network/status?uid=abc123`). This value is embedded directly into the log message with no normalization, truncation, or stripping of query parameters.

**Failed assumption:** The code assumes the logged `path` is a bounded, low-cardinality value suitable for structured logging. In reality it is attacker-controlled and unbounded.

**Exploit flow:**
1. Attacker sends a stream of HTTP requests to any non-internal endpoint (e.g., `POST /network/status`) appending a unique query parameter each time: `?x=1`, `?x=2`, … `?x=N`.
2. Each request passes through `TracingMiddleware`; `path` is `/network/status?x=<unique>`.
3. The `internalPaths[path]` lookup fails (the map holds bare paths like `/health/liveness`), so every entry is emitted at `log.Info`.
4. Every log line is distinct; deduplication systems (ELK, Loki, Splunk, etc.) cannot collapse them.
5. Log volume grows linearly with request rate; query strings can be padded to near the server's URL-length limit (~8 KB each), multiplying storage impact.

**Secondary effect:** The same exact-match check means that sending `GET /health/liveness?x=1` bypasses the `internalPaths` guard and is logged at `Info` instead of `Debug`, further amplifying volume from health-probe paths.

**Existing checks reviewed and shown insufficient:**
- `internalPaths` map (line 55) performs an exact string match on the full URI. Any query parameter appended to a protected path causes the check to miss, so there is no effective suppression path for an attacker-controlled URI.
- No rate limiting, no query-string length cap, and no path normalization exist anywhere in this middleware. [1](#0-0) [2](#0-1) 

### Impact Explanation
- **Log storage inflation:** Each request with a unique query string produces a unique, non-deduplicable log record. At high request rates with padded query strings (up to ~8 KB), storage consumption can be driven up orders of magnitude beyond normal operational volume.
- **Deduplication defeat:** Centralized log platforms rely on message identity for grouping, alerting thresholds, and cost controls. Unique-per-request messages break all of these.
- **Operational noise:** Security and ops teams lose the ability to distinguish real anomalies from attacker-injected noise.
- Severity is **Medium** (griefing / resource exhaustion with no direct fund loss), consistent with the stated scope.

### Likelihood Explanation
- **No authentication required.** The Rosetta API is a public HTTP service; any network-reachable client can send requests.
- **Trivially scriptable.** A single `for` loop with an incrementing counter in the query string is sufficient.
- **No server-side cost to attacker.** Requests can be small (e.g., empty POST body); the cost asymmetry favors the attacker.
- **Repeatable indefinitely** until an out-of-band rate limiter or WAF is deployed.

### Recommendation
1. **Strip or normalize the query string before logging.** Use `request.URL.Path` instead of `request.URL.RequestURI()` so only the path component is recorded:
   ```go
   path := request.URL.Path   // no query string
   ```
2. **Truncate the logged path** to a safe maximum length (e.g., 256 characters) as a defense-in-depth measure.
3. **Fix the `internalPaths` guard** to compare against `request.URL.Path` (not the full URI) so health/metrics paths with appended query strings are still suppressed to `Debug`.
4. Apply an upstream rate limiter or reverse-proxy request-size limit to bound log-line length independently.

### Proof of Concept
```bash
# Send 10,000 requests each with a unique query parameter
for i in $(seq 1 10000); do
  curl -s -o /dev/null -X POST \
    "http://<rosetta-host>:<port>/network/list?uid=$i" \
    -H "Content-Type: application/json" \
    -d '{"metadata":{}}' &
done
wait

# Each produces a distinct Info-level log line such as:
# level=info msg="1.2.3.4 POST /network/list?uid=1 (200) in 3ms"
# level=info msg="1.2.3.4 POST /network/list?uid=2 (200) in 3ms"
# ...
# Log deduplication collapses 0 entries; all 10,000 are stored individually.
```

### Citations

**File:** rosetta/app/middleware/trace.go (L47-47)
```go
		path := request.URL.RequestURI()
```

**File:** rosetta/app/middleware/trace.go (L52-59)
```go
		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
```
