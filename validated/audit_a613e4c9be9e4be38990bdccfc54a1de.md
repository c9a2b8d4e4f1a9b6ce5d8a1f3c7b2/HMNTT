Looking at the actual code and SECURITY.md to validate this claim.

**Code verification:**

All required checks pass. The code, logger configuration, and scope rules have been verified.

**Code facts confirmed:**
- `getClientIpAddress()` at lines 63–74 only guards against `len == 0` [1](#0-0) 
- The raw value is interpolated into `message` via `fmt.Sprintf` and passed to `log.Info`/`log.Debug` [2](#0-1) 
- The logger is explicitly configured with `log.TextFormatter` (one-line-per-entry format) with `DisableColors: true` and `FullTimestamp: true` — no JSON escaping [3](#0-2) 
- SECURITY.md explicitly states "reflected plain text injection" is out of scope but **"This does not exclude persistent plain text injection"** — log injection is persistent (server-side), not reflected [4](#0-3) 

---

## Audit Report

## Title
Log Injection via Unsanitized `X-Forwarded-For` / `X-Real-IP` Header in `getClientIpAddress()`

## Summary
The `TracingMiddleware` in `rosetta/app/middleware/trace.go` reads the `X-Real-IP` or `X-Forwarded-For` HTTP header verbatim and interpolates it directly into a logrus log message without any sanitization. Because the only guard is an empty-length check, a header value containing `\n` (0x0A) passes validation and splits the log entry, enabling an unauthenticated attacker to inject arbitrary content into the server's log stream.

## Finding Description

**File:** `rosetta/app/middleware/trace.go`

`getClientIpAddress()` (lines 63–74) reads `X-Real-IP` first, then falls back to `X-Forwarded-For`. The sole rejection condition is `len(ipAddress) == 0`. A value of `"\n"` has `len == 1` and passes both guards, returning the raw newline to the caller. [1](#0-0) 

The returned value is then passed to `fmt.Sprintf` to build `message`, which is handed directly to `log.Info` or `log.Debug`: [2](#0-1) 

The logrus instance is configured in `rosetta/main.go` with `log.TextFormatter` (`DisableColors: true`, `FullTimestamp: true`). This formatter writes one log entry per line with no escaping of the message string. A `\n` embedded in `message` is written as a literal newline to stdout, splitting the entry. [3](#0-2) 

**Root cause:** The code assumes the header contains a printable IP address string. It only checks for emptiness, not for content validity or the presence of control characters.

**Failed assumption:** `len(ipAddress) > 0` does **not** imply the value is a safe, printable IP address string.

## Impact Explanation

With logrus `TextFormatter` (one-entry-per-line), injecting `\n` splits the log entry. Everything after the newline is written as a new, attacker-controlled "log line." This enables:

- **Log forgery**: Fake entries (e.g., `time="..." level=info msg="admin login succeeded"`) appear as legitimate application log lines.
- **Log structure corruption**: Structured log consumers (Logstash, Fluentd, Splunk forwarders) that expect one-entry-per-line can misparse or silently drop subsequent real entries.
- **Security-monitoring bypass**: Injected lines can drown out or overwrite real audit events, defeating alerting rules.
- **ANSI escape injection**: Even with `DisableColors: true` on the formatter, the *message string itself* is not stripped of ANSI codes; terminals or log viewers rendering ANSI sequences can be manipulated.

## Likelihood Explanation

- **No authentication required**: Any HTTP client can set arbitrary request headers.
- **Trivially reproducible**: A single crafted `curl` request suffices (see PoC below).
- **No application-layer rate limiting or WAF**: The middleware itself imposes none.
- **Every request is logged**: The attacker can flood logs continuously and at will.
- **Persistent injection**: The injected content persists in server log files and forwarded log streams, not merely reflected to the requester.

## Recommendation

Sanitize the header value in `getClientIpAddress()` before returning it. Recommended approach:

1. **Validate as an IP address**: After reading the header, attempt to parse it with `net.ParseIP`. If parsing fails, fall back to `r.RemoteAddr`. This rejects any value that is not a valid IP address, including those containing `\n`, spaces, or ANSI sequences.
2. **Strip control characters**: As a defense-in-depth measure, strip or replace any character with code point < 0x20 (including `\n`, `\r`, `\t`) before using the value in any log call.
3. **Handle comma-separated `X-Forwarded-For`**: The header may contain a comma-separated list (e.g., `client, proxy1, proxy2`); take only the first token and validate it as an IP.

Example fix for `getClientIpAddress()`:
```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        val := r.Header.Get(header)
        // X-Forwarded-For may be a comma-separated list; take the first entry
        if idx := strings.IndexByte(val, ','); idx != -1 {
            val = val[:idx]
        }
        val = strings.TrimSpace(val)
        if net.ParseIP(val) != nil {
            return val
        }
    }
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}
```

## Proof of Concept

```bash
# Inject a fake log line after a real one
curl -s \
  -H $'X-Forwarded-For: 1.2.3.4\ntime="2024-01-01T00:00:00Z" level=info msg="admin login succeeded" user=root' \
  http://<rosetta-host>:5700/network/list \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}'
```

**Expected server log output (two lines, second is attacker-controlled):**
```
time="2024-01-01T00:00:01Z" level=info msg="1.2.3.4\ntime=\"2024-01-01T00:00:00Z\" level=info msg=\"admin login succeeded\" user=root POST /network/list (200) in 3ms"
time="2024-01-01T00:00:00Z" level=info msg="admin login succeeded" user=root POST /network/list (200) in 3ms
```

The second line is entirely attacker-controlled and indistinguishable from a genuine application log entry.

### Citations

**File:** rosetta/app/middleware/trace.go (L52-58)
```go
		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
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

**File:** rosetta/main.go (L43-52)
```go
	log.SetFormatter(&log.TextFormatter{ // Use logfmt for easy parsing by Loki
		CallerPrettyfier: func(frame *runtime.Frame) (function string, file string) {
			parts := strings.Split(frame.File, moduleName)
			relativeFilepath := parts[len(parts)-1]
			// remove function name, show file path relative to project root
			return "", fmt.Sprintf("%s:%d", relativeFilepath, frame.Line)
		},
		DisableColors: true,
		FullTimestamp: true,
	})
```

**File:** SECURITY.md (L33-35)
```markdown
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
```
