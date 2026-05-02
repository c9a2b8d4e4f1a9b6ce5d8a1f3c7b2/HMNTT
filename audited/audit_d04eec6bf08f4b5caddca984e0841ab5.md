### Title
`TracingMiddleware` `internalPaths` Suppression Bypassed via Query String, Enabling Unauthenticated Info-Level Log Flooding

### Summary
`TracingMiddleware` uses `request.URL.RequestURI()` to obtain the request path, which includes the raw query string. The `internalPaths` map is keyed on bare paths (e.g., `/health/liveness`), so any request carrying a query string (e.g., `/health/liveness?x=1`) produces a key that never matches, causing the request to be logged at `log.Info` instead of `log.Debug`. Any unauthenticated external caller can exploit this to flood the info-level log at will, burying legitimate transaction-tracing entries and making chronological reconstruction of real activity infeasible.

### Finding Description
**Exact location:** `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 47 and 55.

```
47:  path := request.URL.RequestURI()   // returns "/health/liveness?x=abc"
...
55:  if internalPaths[path] {           // map key is "/health/liveness" → miss
56:      log.Debug(message)
57:  } else {
58:      log.Info(message)              // ← always taken when query string present
59:  }
```

`internalPaths` is declared at line 19 with exact bare-path keys:
```
var internalPaths = map[string]bool{livenessPath: true, metricsPath: true, readinessPath: true}
// livenessPath  = "/health/liveness"
// readinessPath = "/health/readiness"
```

`net/http`'s `URL.RequestURI()` returns `path?query`, so `/health/liveness?x=1` ≠ `/health/liveness`. The map lookup returns `false`, and `log.Info` is called unconditionally.

**Root cause / failed assumption:** The code assumes `RequestURI()` returns only the path component. It does not — it returns the full request URI including any query string. The correct call to isolate the path is `request.URL.Path`.

**Why existing checks fail:** The `internalPaths` guard is the only suppression mechanism. There is no rate-limiting, no query-string stripping before the lookup, and no authentication on the `/health/*` endpoints. The test suite (trace_test.go lines 36–46) only exercises exact bare-path matches and never tests a query-string variant of an internal path, so the bypass is untested and undetected.

### Impact Explanation
An attacker can inject an unbounded number of `log.Info` entries into the application's structured transaction log. Because Rosetta's info log is the primary audit trail for tracing the chronological sequence of network/transaction API calls, flooding it with thousands of synthetic health-check entries:
- Makes it impossible to reconstruct the true order of legitimate transaction events (the stated "reorganizing transaction history" impact).
- Can exhaust log storage, triggering log rotation that discards older legitimate entries.
- Degrades any log-based alerting or SIEM correlation that relies on info-level events.

Severity: **Medium** (integrity/availability of audit log; no direct fund theft, but forensic reconstruction is destroyed).

### Likelihood Explanation
- **Precondition:** None. The `/health/liveness` endpoint is publicly reachable by design (Kubernetes liveness probes, external monitoring).
- **Skill required:** Zero — a single `curl` loop suffices.
- **Repeatability:** Fully repeatable, stateless, and trivially scriptable at high rate.
- **Detection:** The attack is self-concealing; the flood itself obscures the log entries that would reveal the attack.

### Recommendation
Replace `request.URL.RequestURI()` with `request.URL.Path` on line 47 of `trace.go`:

```go
// Before (vulnerable):
path := request.URL.RequestURI()

// After (fixed):
path := request.URL.Path
```

`URL.Path` contains only the decoded path component, never the query string, so the `internalPaths` map lookup will correctly match `/health/liveness` regardless of any appended query parameters. The full URI (including query string) can still be included in the log message separately if needed for debugging, but the suppression decision must be made on the path alone.

### Proof of Concept

```bash
# Terminal 1: observe the info-level log of the running rosetta service
# (log level must be info or above, which is the default)

# Terminal 2: flood the liveness endpoint with unique query strings
for i in $(seq 1 10000); do
  curl -s "http://<rosetta-host>:<port>/health/liveness?bypass=$i" > /dev/null &
done
wait

# Expected result:
# The info-level log is flooded with 10,000 entries of the form:
#   level=info msg="<ip> GET /health/liveness?bypass=<N> (200) in <duration>"
#
# Contrast with the intended behavior:
#   curl -s "http://<rosetta-host>:<port>/health/liveness"
#   → level=debug (suppressed at default log level, never appears in info log)
#
# The query-string variant bypasses suppression and appears at info level,
# making the legitimate transaction trace entries unsearchable.
```

**Affected lines:** [1](#0-0) [2](#0-1) [3](#0-2)

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
