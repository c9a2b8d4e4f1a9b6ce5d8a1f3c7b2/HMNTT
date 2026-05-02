### Title
IP Address Spoofing in Trace Logs via Unvalidated `X-Forwarded-For` / `X-Real-IP` Headers

### Summary
The `getClientIpAddress()` function in `rosetta/app/middleware/trace.go` unconditionally trusts the `X-Real-IP` and `X-Forwarded-For` HTTP headers without any validation against the actual TCP connection's `RemoteAddr`. Any unprivileged external client can supply arbitrary values in these headers, causing the mirror node's trace logs to record a completely fabricated originating IP address.

### Finding Description
**Exact code location:** `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74. [1](#0-0) 

**Root cause:** The function applies a simple priority chain — `X-Real-IP` → `X-Forwarded-For` → `r.RemoteAddr` — with no verification that the header values are consistent with the actual TCP peer address, and no concept of a "trusted proxy" list.

**Exploit flow:**

1. Attacker sends an HTTP request with either:
   - `X-Real-IP: <spoofed>` set to any value, **or**
   - `X-Real-IP` absent/empty **and** `X-Forwarded-For: <spoofed>` set to any value.
2. `r.Header.Get(xRealIpHeader)` returns `""` (header absent or explicitly empty).
3. `len(ipAddress) == 0` is `true`, so the code falls through to `r.Header.Get(xForwardedForHeader)`.
4. The attacker-controlled value is returned and written directly into the log message at line 52–53. [2](#0-1) 

**Why existing checks fail:** There are none. The code never compares the header value against `r.RemoteAddr`, never validates that the value is a well-formed IP address, and never restricts trust to a known proxy CIDR range.

### Impact Explanation
The logged client IP is the sole attribution record written to the mirror node trace log for every non-internal request. An attacker can:
- **Frame another host** by logging a victim's IP as the source of malicious API calls.
- **Evade attribution** by logging a non-routable or third-party IP, making forensic investigation misleading or impossible.
- **Poison audit trails** systematically across all requests, undermining the integrity of the exported trace records that operators rely on for incident response.

Severity: **Medium** — no direct code execution or data exfiltration, but log integrity is a security control; its compromise directly degrades the "incorrect or missing records exported to mirror nodes" threat surface.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only the ability to send an HTTP request to the Rosetta endpoint, which is the definition of an unprivileged external user. No authentication, no special network position, and no prior knowledge of the system is required. The attack is trivially repeatable with a single `curl` command and leaves no reliable forensic trace.

### Recommendation
Replace the unconditional header trust with a trusted-proxy model:

1. Maintain a configurable allowlist of trusted upstream proxy CIDRs (e.g., the cluster's ingress CIDR).
2. Only accept `X-Real-IP` / `X-Forwarded-For` when `r.RemoteAddr` falls within a trusted CIDR.
3. If `r.RemoteAddr` is not a trusted proxy, ignore both headers and use `r.RemoteAddr` directly.
4. Additionally, validate that the extracted value is a syntactically valid IP address (using `net.ParseIP`) before logging it, and fall back to `r.RemoteAddr` on parse failure.

### Proof of Concept
```bash
# Log a spoofed IP (e.g., 8.8.8.8) in the mirror node trace records
curl -H "X-Forwarded-For: 8.8.8.8" \
     http://<rosetta-host>/network/status

# Alternatively, explicitly empty X-Real-IP to force XFF fallback
curl -H "X-Real-IP: " \
     -H "X-Forwarded-For: 192.168.1.1" \
     http://<rosetta-host>/network/status
```
After either request, the mirror node trace log will record `8.8.8.8` (or `192.168.1.1`) as the originating client IP instead of the attacker's real address.

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
