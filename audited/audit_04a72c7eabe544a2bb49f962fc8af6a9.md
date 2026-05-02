### Title
ANSI Escape Sequence Injection via Unsanitized `X-Real-IP` Header in `TracingMiddleware`

### Summary
`TracingMiddleware()` in `rosetta/app/middleware/trace.go` reads the `X-Real-IP` header verbatim and interpolates it directly into a log message string without any validation or sanitization. Because logrus does not strip ANSI escape sequences from message content, an unauthenticated external attacker can inject terminal control codes that corrupt, overwrite, or manipulate log output when operators inspect logs in a terminal emulator.

### Finding Description
**Code path:**

- `getClientIpAddress()` (lines 63–74): reads `r.Header.Get(xRealIpHeader)` with zero validation — no IP format check, no character allowlist, no stripping of control characters. [1](#0-0) 

- `TracingMiddleware()` (lines 52–58): the raw return value is placed directly into `fmt.Sprintf(...)` and then passed to `log.Info(message)` / `log.Debug(message)`. [2](#0-1) 

**Root cause:** The failed assumption is that the `X-Real-IP` header will always contain a well-formed IP address string. In reality, HTTP headers are arbitrary byte sequences under the caller's control. No existing check validates or sanitizes the value before it reaches the logger.

**Why existing checks are insufficient:** The only branching logic (`internalPaths[path]`) controls log level (Debug vs Info), not content sanitization. `net.SplitHostPort` is only called as a fallback when both `X-Real-IP` and `X-Forwarded-For` are absent — it is never applied to sanitize the header values themselves. [3](#0-2) 

**Exploit flow:**
1. Attacker sends any HTTP request to the Rosetta endpoint with a crafted header, e.g.:
   ```
   X-Real-IP: \x1b[2J\x1b[H[INJECTED]
   ```
2. `getClientIpAddress` returns the raw string including the escape sequences.
3. `fmt.Sprintf` embeds it into the log message.
4. `log.Info(message)` writes it to stdout/stderr.
5. Any terminal emulator rendering the log stream interprets the ANSI codes (clear screen, cursor repositioning, color changes, etc.).

### Impact Explanation
An operator tailing logs in a terminal (`tail -f`, `journalctl -f`, etc.) will have their terminal state corrupted: screen cleared, cursor repositioned, prior log lines overwritten, or false log entries visually injected. This constitutes griefing of operator tooling — incident response and audit trails become unreliable. No economic damage to network users occurs, matching the stated scope of "medium: griefing with no economic damage."

### Likelihood Explanation
Preconditions are minimal: the attacker needs only network access to the Rosetta HTTP port (no authentication, no special role). The attack is trivially repeatable with a single `curl` command. Any internet-exposed deployment is at risk. The attack is stateless and requires no prior knowledge of the system beyond the endpoint URL.

### Recommendation
Sanitize the IP address value returned by `getClientIpAddress` before logging:

1. **Validate as IP**: After reading the header, parse it with `net.ParseIP()`. If parsing fails, discard the header value and fall through to the next source (or log a placeholder like `"invalid-ip"`).
2. **Strip control characters**: As a defense-in-depth measure, strip or percent-encode any byte below `0x20` (including `\x1b`) from any string sourced from user-controlled input before passing it to the logger.
3. **Use a structured logger field**: Pass the IP as a structured logrus field (`log.WithField("client_ip", sanitized).Info(...)`) rather than interpolating it into the message string, which makes injection harder to exploit visually.

### Proof of Concept
```bash
# Clears the operator's terminal and injects a fake log line
curl -H $'X-Real-IP: \x1b[2J\x1b[H[FAKE] 2024/01/01 00:00:00 INFO no errors found' \
     http://<rosetta-host>:<port>/network/status \
     -X POST -H "Content-Type: application/json" -d '{}'
```
When an operator has `tail -f` or `journalctl -f` open in a terminal, the injected ANSI sequences execute immediately upon the log line being written, clearing the screen and displaying attacker-controlled text.

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
