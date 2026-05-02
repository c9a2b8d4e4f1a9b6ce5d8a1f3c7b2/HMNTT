The code is confirmed. Here is the audit result:

---

Audit Report

## Title
Log Injection via Unsanitized `X-Forwarded-For` / `X-Real-IP` Header in `getClientIpAddress()`

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` accepts the `X-Real-IP` and `X-Forwarded-For` header values verbatim. The only guard is an empty-string check (`len(ipAddress) == 0`). Any non-empty value — including one containing `\n` — passes through and is interpolated directly into a logrus log message, enabling an unauthenticated attacker to inject arbitrary content into the application log stream.

## Finding Description

**File:** `rosetta/app/middleware/trace.go`

`getClientIpAddress()` (lines 63–74) reads `X-Real-IP`, falls back to `X-Forwarded-For`, and falls back to `r.RemoteAddr`. The only rejection condition is `len(ipAddress) == 0`. [1](#0-0) 

A header value of `"\n"` has `len == 1`, so it passes both guards and is returned as-is.

The returned value is then interpolated into `message` via `fmt.Sprintf` and passed directly to `log.Info` / `log.Debug` (logrus) with no escaping, stripping, or IP-format validation at any point. [2](#0-1) 

**Root cause:** The code assumes the header contains a valid IP address string. It only checks for emptiness, not for content validity or the presence of control characters.

**Failed assumption:** `len(ipAddress) > 0` does **not** imply the value is a safe, printable IP address string.

## Impact Explanation

When logrus uses its default `TextFormatter`, each log entry is a single line. Injecting `\n` splits the entry, and anything after the newline is written as a new, attacker-controlled "log line." This enables:

- **Log forgery**: Fake entries (e.g., `time="..." level=info msg="admin login succeeded"`) appear as legitimate application log lines.
- **Log structure corruption**: Structured log parsers (Logstash, Fluentd, Splunk forwarders) that expect one-entry-per-line can misparse or drop subsequent real entries.
- **Security-monitoring bypass**: Injected lines can drown out or overwrite real audit events, defeating alerting rules.
- **ANSI escape injection**: Terminals or log viewers rendering ANSI codes can be manipulated (cursor movement, color flooding) causing display corruption.

## Likelihood Explanation

- **No authentication required**: Any HTTP client can set arbitrary headers.
- **Trivially reproducible**: A single `curl` command suffices (see PoC).
- **No application-layer rate-limiting or WAF**: The middleware itself imposes none.
- **Repeatable at will**: Every request is logged, so the attacker can flood logs continuously.

## Recommendation

Validate the header value as a proper IP address before use. Replace the raw header read with a `net.ParseIP()` check:

```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        val := r.Header.Get(header)
        // Take only the first address in a comma-separated list
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

This ensures only syntactically valid IP addresses (no control characters, no newlines) are ever passed to the logger.

## Proof of Concept

```bash
# Inject a fake log line after a real one
curl -s \
  -H $'X-Real-IP: 1.2.3.4\ntime="2024-01-01T00:00:00Z" level=info msg="admin login succeeded" user=root' \
  http://<target>/network/status
```

Expected log output (logrus TextFormatter):
```
time="..." level=info msg="1.2.3.4
time="2024-01-01T00:00:00Z" level=info msg="admin login succeeded" user=root GET /network/status (200) in 1ms"
```

The second line appears as a fully independent, attacker-controlled log entry to any downstream log consumer.

### Citations

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
