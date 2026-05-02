### Title
Unvalidated `X-Real-IP` Header Written Verbatim to Logs via `TracingMiddleware`

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` reads the `X-Real-IP` header directly from the incoming HTTP request with no format validation, length check, or sanitization. The raw header value is then interpolated verbatim into every log entry produced by `TracingMiddleware`. Any unprivileged client that can reach the Rosetta API endpoint can supply an arbitrary string in this header, permanently polluting access logs with attacker-controlled content and destroying the integrity of IP-based audit trails.

### Finding Description
**Exact code path:**

`getClientIpAddress()` (lines 63–74) unconditionally trusts the `X-Real-IP` header:

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)   // line 64 — no validation
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)
    }
    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }
    return ipAddress   // raw, attacker-controlled string
}
```

`TracingMiddleware` (lines 52–58) then writes this value directly into every log entry:

```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)
log.Info(message)
```

**Root cause:** The function assumes `X-Real-IP` is set only by a trusted reverse proxy. There is no IP-format validation (e.g., `net.ParseIP`), no length cap, and no allowlist. The test suite (`trace_test.go` lines 52–54) explicitly confirms the design intent of reflecting the header into logs, but never tests malicious input.

**Failed assumption:** The code assumes a reverse proxy will always be present and will strip or overwrite client-supplied `X-Real-IP` values. This assumption is not enforced anywhere in the codebase. `main.go` (lines 217–219) shows `TracingMiddleware` wraps the router directly with no proxy-trust configuration.

**Exploit flow:**
1. Attacker sends any HTTP request to the Rosetta API with a crafted header: `X-Real-IP: FAKE_ATTACKER_STRING`
2. `getClientIpAddress()` returns `"FAKE_ATTACKER_STRING"` without any check.
3. `TracingMiddleware` logs: `FAKE_ATTACKER_STRING GET /network/list (200) in 1.2ms`
4. Every request the attacker sends produces a log line with their chosen fake IP.

**Why existing checks fail:** There are none. Go's `net/http` library strips bare CRLF from header values (mitigating newline injection), but arbitrary printable strings — including fake IPs, hostnames, or misleading identifiers — pass through unmodified.

### Impact Explanation
Operators rely on IP addresses in access logs for incident response, abuse detection, rate-limit enforcement, and forensic attribution. By injecting arbitrary strings, an attacker can: (a) impersonate legitimate IPs to frame other parties, (b) flood logs with noise to obscure their real `RemoteAddr`, and (c) corrupt SIEM/log-aggregation pipelines that parse the IP field. This directly degrades log integrity with no economic cost to the attacker.

### Likelihood Explanation
The precondition is trivially met: any HTTP client that can reach the Rosetta port (default open, no authentication required by the Rosetta spec) can exploit this. No credentials, tokens, or special network position are needed. The attack is repeatable at zero cost per request and requires a single line of curl. Deployments without a hardening reverse proxy (common in development, testing, or direct-exposure scenarios) are fully exposed.

### Recommendation
Validate the extracted IP string before using it. After `getClientIpAddress()` returns, parse and verify it is a valid IP address:

```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        val := r.Header.Get(header)
        // Take only the first token (X-Forwarded-For may be comma-separated)
        if ip := net.ParseIP(strings.TrimSpace(strings.SplitN(val, ",", 2)[0])); ip != nil {
            return ip.String()
        }
    }
    ipAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ipAddress
}
```

Additionally, document and enforce (via deployment configuration) that the service must sit behind a trusted reverse proxy that strips and re-sets `X-Real-IP` from upstream.

### Proof of Concept
```bash
# Direct request with arbitrary X-Real-IP value
curl -s -X POST http://<rosetta-host>:<port>/network/list \
  -H "Content-Type: application/json" \
  -H "X-Real-IP: INJECTED_FAKE_192.0.2.1_ATTACKER" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}'

# Observe server logs — the injected string appears verbatim:
# time="..." level=info msg="INJECTED_FAKE_192.0.2.1_ATTACKER POST /network/list (200) in 3ms"
```

The log entry now contains the attacker-controlled string instead of the real client IP, with no server-side rejection or sanitization. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** rosetta/app/middleware/trace_test.go (L52-54)
```go
		headers:  map[string]string{xRealIpHeader: clientIp},
		path:     defaultPath,
		messages: []string{clientIp},
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
