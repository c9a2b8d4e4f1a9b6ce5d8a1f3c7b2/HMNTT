### Title
Unsanitized Tab Character Injection via `X-Forwarded-For` Causes Log Field Misparsing in `getClientIpAddress()`

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` reads the `X-Forwarded-For` (or `X-Real-IP`) header value verbatim and returns it without any sanitization. The raw value is interpolated directly into a space-delimited log message string. Because RFC 7230 permits HTAB (`\t`) within header field values and Go's `net/http` passes them through unmodified, an unprivileged attacker can inject a tab character into the header, causing the resulting log line to contain an embedded tab that breaks whitespace-splitting log parsers and corrupts IP-field correlation used for network partition detection.

### Finding Description

**Exact code path:**

`getClientIpAddress()` — `rosetta/app/middleware/trace.go` lines 63–74:
```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)   // raw, unsanitized
    }
    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }
    return ipAddress   // returned with any embedded control chars intact
}
```

The returned value is immediately embedded into the log message at lines 52–53:
```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

**Root cause / failed assumption:** The code assumes the header value is a well-formed IP address string. RFC 7230 §3.2.6 explicitly allows HTAB within `field-content`:
```
field-content = field-vchar [ 1*( SP / HTAB ) field-vchar ]
```
Go's `net/http` / `textproto` layer does not strip embedded tabs from header values, so `r.Header.Get("X-Forwarded-For")` faithfully returns `"1.2.3.4\t5.6.7.8"`.

**Exploit flow:**
1. Attacker sends: `GET /network/list HTTP/1.1\r\nX-Forwarded-For: 1.2.3.4\t5.6.7.8\r\n\r\n`
2. `getClientIpAddress()` returns `"1.2.3.4\t5.6.7.8"` (no validation).
3. `fmt.Sprintf` produces: `"1.2.3.4\t5.6.7.8 GET /network/list (200) in 1ms"`
4. Logrus writes the literal tab to the log output (it does not escape control characters in message strings).
5. The log line now contains an embedded tab, shifting all subsequent fields one position to the right for any parser that tokenizes on whitespace.

**Existing checks — shown insufficient:**
- `len(ipAddress) == 0` only guards against an empty string; it does not validate content.
- `net.SplitHostPort` is only reached when both proxy headers are absent.
- The test suite (`trace_test.go`) only exercises clean IP strings (`10.0.0.100`, `192.0.2.1`); no test covers control-character injection.
- No middleware, reverse-proxy stripping, or input validation layer is present in this code path.

### Impact Explanation
Any downstream log-analysis pipeline that tokenizes on whitespace (e.g., `awk '{print $1}'`, Splunk field extraction, Elastic Logstash `grok` patterns, custom network-partition detectors that correlate source IPs across log lines) will misidentify the client IP field. The injected tab shifts the `method`, `path`, and `status` fields, so:
- IP-based correlation queries silently operate on wrong data.
- Automated network-partition detection that relies on counting unique IPs per time window receives corrupted input, potentially masking a real partition event or generating false positives.
- An attacker can also use this to make their own requests appear to originate from an internal IP by crafting the tab-split to place a trusted address in the field position the parser reads as the IP.

### Likelihood Explanation
- **Precondition:** The service must be reachable by the attacker (any public or semi-public deployment). No authentication is required.
- **Trigger:** A single HTTP request with a crafted `X-Forwarded-For` header suffices; the header is valid per RFC 7230 and will not be rejected by Go's HTTP stack.
- **Repeatability:** Trivially repeatable; the attacker can sustain log corruption for the duration of any monitoring window.
- **Attacker capability:** Zero privilege required; a script-kiddie-level attacker can exploit this with `curl`.

### Recommendation
Sanitize the header value in `getClientIpAddress()` before returning it. The minimal fix is to validate that the returned string is a well-formed IP address using `net.ParseIP` (after splitting on `,` for multi-value `X-Forwarded-For`), and fall back to `RemoteAddr` if validation fails:

```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        raw := r.Header.Get(header)
        if raw == "" {
            continue
        }
        // X-Forwarded-For may be a comma-separated list; take the first entry.
        candidate := strings.TrimSpace(strings.SplitN(raw, ",", 2)[0])
        if ip := net.ParseIP(candidate); ip != nil {
            return ip.String()   // canonical, control-char-free representation
        }
    }
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}
```

This ensures only a valid, canonicalized IP address ever reaches the log formatter.

### Proof of Concept
```bash
# Inject a tab character into X-Forwarded-For
curl -s -o /dev/null \
  -H $'X-Forwarded-For: 1.2.3.4\t5.6.7.8' \
  http://<rosetta-host>/network/list

# Observe the resulting log line (logrus text format):
# time="..." level=info msg="1.2.3.4	5.6.7.8 GET /network/list (200) in Xms"
#                                    ^tab here

# A whitespace-splitting parser sees:
# token[0] = "1.2.3.4"        ← IP (correct by accident)
# token[1] = "5.6.7.8"        ← expected: method
# token[2] = "GET"             ← expected: path
# token[3] = "/network/list"   ← expected: status code
# → all fields after the IP are shifted; IP-correlation logic reads wrong data
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L52-53)
```go
		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
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
