### Title
IP Spoofing via User-Controlled `X-Forwarded-For` Enabled by Empty `X-Real-IP` Fallback in `getClientIpAddress()`

### Summary
The `getClientIpAddress()` function in `rosetta/app/middleware/trace.go` unconditionally trusts the `X-Real-IP` and `X-Forwarded-For` HTTP headers supplied by the client. An unprivileged external attacker can send `X-Real-IP` with an empty value and `X-Forwarded-For` with a forged IP; the `len(ipAddress) == 0` check silently falls through to the forged value, which is then written to the audit/trace log as the authoritative client address. No proxy-trust validation or header sanitization exists anywhere in the call chain.

### Finding Description
**Exact code path:** `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74.

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)       // line 64 – attacker sets "" here

    if len(ipAddress) == 0 {                        // line 66 – true for empty string
        ipAddress = r.Header.Get(xForwardedForHeader) // line 67 – attacker-controlled value used
    }

    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }

    return ipAddress
}
```

**Root cause / failed assumption:** The code assumes that if `X-Real-IP` is absent (zero-length), it is safe to fall back to `X-Forwarded-For`. It does not distinguish between "header not sent" and "header sent with an empty value." In Go's `net/http`, `r.Header.Get()` returns `""` for both cases, so `len(ipAddress) == 0` is `true` for an explicitly empty `X-Real-IP: ` header. Neither header is validated against a trusted-proxy allowlist, and no canonicalization or format check is applied to the returned value.

**Exploit flow:**
1. Attacker crafts a request with two headers:
   - `X-Real-IP: ` (present but empty)
   - `X-Forwarded-For: 192.0.2.1` (arbitrary forged address)
2. `r.Header.Get(xRealIpHeader)` returns `""`.
3. `len("") == 0` → fallback branch executes.
4. `r.Header.Get(xForwardedForHeader)` returns `"192.0.2.1"`.
5. `TracingMiddleware` logs `"192.0.2.1 POST /network/status (200) in 3ms"`.

The resolved IP in the log is entirely attacker-controlled. Because the log only records the resolved string (line 52–53), there is no way for an analyst to distinguish a forged entry from a legitimate one.

**Why existing checks are insufficient:** There are no existing checks. The function performs no:
- Trusted-proxy IP range validation
- Header value format/IP-address validation
- Distinction between header-absent and header-empty

### Impact Explanation
The trace log produced by `TracingMiddleware` is the sole source of client-IP attribution for every Rosetta API request. An attacker who can forge this value can:
- Attribute their own requests to any IP address (e.g., a known legitimate node, an internal service, or a non-existent host), defeating IP-based audit trails.
- Systematically misrepresent the origin of requests that query or submit transactions, making forensic reconstruction of "who did what" unreliable.
- Evade IP-based rate-limit or anomaly-detection systems that consume these logs downstream.

In the context of a Rosetta/mirror-node deployment where the log is the primary record of API activity, this constitutes a meaningful integrity violation of the transaction-request audit history.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only the ability to send HTTP requests to the Rosetta endpoint (standard internet access if the port is exposed). No authentication, no special role, no prior knowledge of the system is required. The technique is trivially repeatable on every request and requires no timing dependency or race condition. Any HTTP client (curl, Python requests, etc.) can set arbitrary headers.

### Recommendation
1. **Trust only the real TCP peer address by default.** Use `r.RemoteAddr` as the authoritative IP unless the request arrives from a known, configured trusted-proxy CIDR range.
2. **Validate trusted-proxy headers only when the peer is trusted.** Maintain an explicit allowlist of proxy IPs/CIDRs; only read `X-Real-IP` / `X-Forwarded-For` when `r.RemoteAddr` matches an entry in that list.
3. **Validate the extracted value.** After extraction, parse the result with `net.ParseIP()` and fall back to `r.RemoteAddr` if parsing fails or the value is empty.
4. **Treat empty-string header values as absent.** The current `len(ipAddress) == 0` check already handles absence; ensure the same branch is taken for whitespace-only values (`strings.TrimSpace`).

### Proof of Concept
```bash
# Forge the logged client IP to 10.0.0.1 while connecting from any real IP
curl -s \
  -H "X-Real-IP: " \
  -H "X-Forwarded-For: 10.0.0.1" \
  http://<rosetta-host>:<port>/network/status \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}'

# Expected log line (from TracingMiddleware):
# INFO  10.0.0.1 POST /network/status (200) in Xms
#
# Actual connecting IP is never recorded; 10.0.0.1 appears as the client.
``` [1](#0-0) [2](#0-1)

### Citations

**File:** rosetta/app/middleware/trace.go (L43-60)
```go
func TracingMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		start := time.Now()
		clientIpAddress := getClientIpAddress(request)
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
	})
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
