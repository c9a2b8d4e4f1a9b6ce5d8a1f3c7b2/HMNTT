### Title
ANSI Escape Code Injection via Unsanitized `X-Real-IP`/`X-Forwarded-For` Headers in `TracingMiddleware`

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` reads the `X-Real-IP` and `X-Forwarded-For` HTTP headers without any sanitization and embeds their raw values directly into log messages via `fmt.Sprintf`. An unprivileged external attacker can inject ANSI escape sequences into these headers, which are then written to logs and interpreted by terminal emulators used by operators, enabling log corruption and log forgery.

### Finding Description
**Code path:**

- `getClientIpAddress` (lines 63–74): reads `X-Real-IP` then `X-Forwarded-For` with no validation — returns the raw string verbatim.
- `TracingMiddleware` (lines 52–53): passes the raw return value directly into `fmt.Sprintf`:
  ```go
  message := fmt.Sprintf("%s %s %s (%d) in %s",
      clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
  ```
- Lines 56–58: the composed `message` is passed to `log.Info` / `log.Debug` (logrus), which does **not** strip ANSI escape codes from message content.

**Root cause:** The failed assumption is that `X-Real-IP` / `X-Forwarded-For` contain only valid IP address strings. In practice, any HTTP client can set these headers to arbitrary byte sequences including ANSI control codes (`\x1b[...m`). There is zero sanitization anywhere in the rosetta codebase (confirmed: no matches for `sanitize`, `strip`, `escape`, or IP validation in `rosetta/**/*.go`).

**Why existing checks fail:** The only alternative path — `net.SplitHostPort(r.RemoteAddr)` (line 71) — is only reached when *both* headers are absent. When either header is present, its raw value is used unconditionally.

### Impact Explanation
- **Log corruption:** ANSI codes like `\x1b[2J` (clear screen) or `\x1b[1A` (cursor up) corrupt terminal output for operators tailing logs, hiding legitimate entries.
- **Log forgery:** An attacker can craft a header value that, when rendered in a terminal, makes a fake log line appear (e.g., injecting a newline + ANSI reset to simulate a clean `INFO` entry with attacker-controlled content), undermining audit trails for transaction gossip monitoring.
- **Severity:** Medium — does not directly compromise transaction integrity, but degrades the integrity of the operational observability layer that operators rely on to detect gossip anomalies.

### Likelihood Explanation
- **Precondition:** None beyond network access to the Rosetta API endpoint. No authentication, no special role.
- **Feasibility:** Trivial — a single HTTP request with a crafted `X-Real-IP` header suffices.
- **Repeatability:** 100% — the code path is exercised on every non-internal request.

### Recommendation
Sanitize the IP address value returned by `getClientIpAddress` before embedding it in log messages. The minimal fix is to validate it as a legitimate IP address using `net.ParseIP` (or accept only the first comma-separated token from `X-Forwarded-For` and validate that), falling back to `"unknown"` on failure:

```go
func getClientIpAddress(r *http.Request) string {
    raw := r.Header.Get(xRealIpHeader)
    if len(raw) == 0 {
        raw = r.Header.Get(xForwardedForHeader)
        // X-Forwarded-For may be a comma-separated list; take the first entry
        if idx := strings.Index(raw, ","); idx != -1 {
            raw = raw[:idx]
        }
    }
    raw = strings.TrimSpace(raw)
    if ip := net.ParseIP(raw); ip != nil {
        return ip.String()
    }
    // fallback to RemoteAddr
    addr, _, _ := net.SplitHostPort(r.RemoteAddr)
    return addr
}
```

This ensures only valid IP address strings ever reach the log formatter.

### Proof of Concept
```bash
# Inject ANSI clear-screen + fake log line into operator terminal
curl -s http://<rosetta-host>:<port>/network/list \
  -H 'Content-Type: application/json' \
  -H $'X-Real-IP: 1.2.3.4\x1b[2J\x1b[HINFO[fake] legitimate-looking gossip entry ip=10.0.0.1' \
  -d '{}'
```

When an operator runs `tail -f` on the log file in a terminal, the ANSI sequences are interpreted: the screen clears and the forged line appears as if it were a real log entry, while the actual log entry for this request is hidden. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L52-53)
```go
		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

**File:** rosetta/app/middleware/trace.go (L55-59)
```go
		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
```

**File:** rosetta/app/middleware/trace.go (L63-74)
```go
func getClientIpAddress(r *http.Request) string {
	ipAddress := r.Header.Get(xRealIpHeader)

	if len(ipAddress) == 0 {
		ipAddress = r.Header.Get(xForwardedForHeader)
	}

	if len(ipAddress) == 0 {
		ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
	}

	return ipAddress
```
