The code references are accurate. Let me verify all claims against the actual source before rendering a verdict.

**Verified facts:**

1. `getClientIpAddress()` at lines 63–74 of `rosetta/app/middleware/trace.go` reads `X-Real-IP` then `X-Forwarded-For` with zero sanitization. [1](#0-0) 

2. The unsanitized value is interpolated directly into the log message passed to `log.Info()`. [2](#0-1) 

3. `DisableColors: true` is set in `configLogger()` in `rosetta/main.go`. This flag only suppresses logrus's own ANSI level-prefix coloring; it performs no sanitization of the message string itself. [3](#0-2) 

4. `request.URL.RequestURI()` returns a percent-encoded URI, so `\x1b` in the path becomes `%1b` — safe. The header vector is the only exploitable path. [4](#0-3) 

The SECURITY.md excludes "Reflected plain text injection (e.g. URL parameters, path, etc.)" but this is **server-side log injection**, not content reflected back to a client — that exclusion does not apply here. [5](#0-4) 

---

Audit Report

## Title
ANSI Escape Sequence Injection via Unsanitized HTTP Headers in `TracingMiddleware`

## Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` logs the client IP address taken verbatim from the `X-Real-IP` or `X-Forwarded-For` HTTP request headers. No control-character stripping is performed before the value is written to the log. An unauthenticated attacker can embed ANSI terminal escape sequences in these headers, causing them to be written into log output and rendered by any terminal or log viewer that interprets ANSI codes.

## Finding Description
**Vulnerable code path:**

`getClientIpAddress()` (lines 63–74) reads the IP directly from attacker-controlled headers:

```go
ipAddress := r.Header.Get(xRealIpHeader)
if len(ipAddress) == 0 {
    ipAddress = r.Header.Get(xForwardedForHeader)
}
``` [6](#0-5) 

The returned value is interpolated unsanitized into the log message:

```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)
log.Info(message)
``` [2](#0-1) 

**Why the existing mitigation fails:**

`DisableColors: true` in `configLogger()` only prevents logrus from prepending its own ANSI color codes to the log-level prefix. It applies no transformation to the message string content. Attacker-supplied escape sequences pass through entirely unmodified. [3](#0-2) 

**Why the URL path is not the vector:**

`request.URL.RequestURI()` returns a percent-encoded URI, so `ESC` (`\x1b`) in the path is encoded as `%1b` and is harmless. Only the header values are unencoded. [4](#0-3) 

## Impact Explanation
An unauthenticated attacker can:
- **Overwrite prior log lines** using carriage-return (`\r`) or cursor-up (`\x1b[A`) sequences, erasing evidence of earlier requests from operator terminals.
- **Inject fake log entries** that appear to originate from legitimate IPs or show false HTTP status codes, misleading incident responders.
- **Corrupt terminal output** for operators tailing logs in real time, degrading their ability to monitor the node and potentially masking concurrent attacks.

No funds are directly at risk, but operator visibility is compromised, which can facilitate or conceal other attacks.

## Likelihood Explanation
- Requires no authentication or special privileges — any HTTP client can set arbitrary request headers.
- If the Rosetta service is directly internet-exposed (no reverse proxy that strips or overwrites `X-Real-IP`/`X-Forwarded-For`), exploitation is trivial and repeatable with a single HTTP request.
- Even behind a proxy, many common configurations (nginx `proxy_set_header X-Real-IP $remote_addr` combined with a client-controlled upstream) forward these headers unchanged.

## Recommendation
Sanitize the IP string returned by `getClientIpAddress()` before it is used in any log message. The minimal fix is to strip or replace all non-printable and non-ASCII characters:

```go
import "regexp"

var nonPrintable = regexp.MustCompile(`[^\x20-\x7E]`)

func sanitize(s string) string {
    return nonPrintable.ReplaceAllString(s, "")
}
```

Apply `sanitize()` to `clientIpAddress` before constructing the log message in `TracingMiddleware`. Alternatively, validate that the value is a well-formed IP address (using `net.ParseIP`) and fall back to a safe placeholder if it is not.

## Proof of Concept
```bash
# Overwrite the previous log line in a terminal tailing the log
curl -H $'X-Real-IP: \x1b[1A\x1b[2K192.0.2.1 GET /fake 200 0ms' \
     http://<rosetta-host>:<port>/network/list
```

When an operator runs `docker logs -f` or `tail -f` on the Rosetta container, the terminal processes the escape sequences: cursor-up (`\x1b[1A`) moves to the previous line, erase-line (`\x1b[2K`) clears it, and the remainder of the header value is rendered as a fabricated log entry in its place.

### Citations

**File:** rosetta/app/middleware/trace.go (L47-47)
```go
		path := request.URL.RequestURI()
```

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
