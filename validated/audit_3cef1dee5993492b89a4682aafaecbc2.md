The code references are accurate. Let me verify the key facts:

- `getClientIpAddress()` at lines 63–74 reads `X-Real-IP` then `X-Forwarded-For` with zero sanitization. [1](#0-0) 
- `TracingMiddleware` at lines 52–53 directly interpolates the raw return value into `fmt.Sprintf` and passes it to `log.Info`/`log.Debug`. [2](#0-1) 
- The test suite only exercises valid IP strings (`clientIp = "10.0.0.100"`) with no malicious input coverage. [3](#0-2) 
- The SECURITY.md explicitly excludes "Reflected plain text injection" but states **"This does not exclude persistent plain text injection"** — log injection is persistent (logs are stored/forwarded). [4](#0-3) 

---

# Audit Report

## Title
Unsanitized `X-Forwarded-For` / `X-Real-IP` Header Values Logged Directly — ANSI Escape Sequence Injection in Access Logs

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` returns the raw, unvalidated value of the `X-Real-IP` or `X-Forwarded-For` header. This value is directly interpolated into a log message and emitted via logrus. An unauthenticated attacker can inject ANSI escape sequences or fake log lines into the server's access log by crafting these headers, corrupting terminal-based log viewers and pattern-based log parsers.

## Finding Description
**Exact code path:**

- `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74: reads `X-Real-IP` then `X-Forwarded-For` with no validation, no allowlist, no character stripping, and returns the raw string verbatim.
- `TracingMiddleware`, lines 52–53: the raw return value is directly interpolated via `fmt.Sprintf("%s %s %s (%d) in %s", clientIpAddress, ...)` and passed to `log.Info(message)` or `log.Debug(message)`.

**Root cause:** The function assumes HTTP header values are well-formed IP address strings. No IP format validation, no regex check, and no control-character stripping is applied anywhere in the call chain.

**Why existing checks fail:** Go's `net/http` parser rejects bare `\r\n` (CRLF injection) but does **not** strip other control characters including `\x1b` (ESC), which begins ANSI escape sequences. The test suite (`trace_test.go` lines 52–58) only exercises valid IP strings and provides no coverage for malicious input. There is no proxy trust list restricting which clients may set these headers.

## Impact Explanation
The direct impact is **log integrity corruption**. Operators relying on access logs to audit Rosetta API calls (e.g., `/block`, `/block/transaction`) and their source IPs cannot trust the IP-address field of any log line. For deployments where access logs feed into SIEM tools or audit pipelines using pattern-based parsing, injected ANSI sequences or embedded fake log lines can cause:
- Misattribution of API calls to spoofed source IPs.
- Silent suppression of real log entries in ANSI-rendering terminal viewers.
- Misparsing of log lines in regex-based log parsers, breaking incident-response workflows.

This does not affect underlying blockchain data but undermines the operational audit trail.

## Likelihood Explanation
Exploitation requires only the ability to send an HTTP request to the Rosetta endpoint — no credentials, no special network position beyond TCP reachability. The only precondition is that the service is deployed without a sanitizing reverse proxy that strips or overwrites `X-Forwarded-For` before it reaches the Go application. Many Kubernetes/Docker deployments pass these headers through from untrusted clients. The attack is trivially repeatable with a single `curl` command.

## Recommendation
In `getClientIpAddress()`, validate the returned string against a strict IP address allowlist before returning it. Use `net.ParseIP()` to accept only well-formed IPv4/IPv6 addresses, and fall back to `r.RemoteAddr` if the header value fails validation:

```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        val := r.Header.Get(header)
        if ip := net.ParseIP(strings.TrimSpace(val)); ip != nil {
            return ip.String()
        }
    }
    ipAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ipAddress
}
```

This ensures only valid, normalized IP strings ever reach the log sink, eliminating the injection surface entirely.

## Proof of Concept
```bash
curl -H $'X-Forwarded-For: \x1b[2J\x1b[H\x1b[32m[INFO]\x1b[0m 2026-05-01T00:00:00Z fake-ip GET /block/transaction (200) in 1ms' \
     http://<rosetta-host>/network/list
```
On any terminal or log viewer that renders ANSI codes, this clears the screen (`\x1b[2J`), repositions the cursor (`\x1b[H`), and displays the attacker-controlled fake log entry in green, making the real log entry invisible. The injected string also breaks any regex-based log parser expecting the `IP METHOD PATH (STATUS) in DURATION` format.

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

**File:** rosetta/app/middleware/trace_test.go (L52-58)
```go
		headers:  map[string]string{xRealIpHeader: clientIp},
		path:     defaultPath,
		messages: []string{clientIp},
	}, {
		headers:  map[string]string{xForwardedForHeader: clientIp},
		path:     defaultPath,
		messages: []string{clientIp},
```

**File:** SECURITY.md (L33-35)
```markdown
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
- This does not exclude persistent plain text injection.
```
