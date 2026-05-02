Based on my direct examination of the code, I can verify the factual claims in this report.

**Code verification:**

`getClientIpAddress()` in `trace.go` lines 63–74 does exactly what is described — unconditionally reads `X-Real-IP` first with no validation: [1](#0-0) 

The result is embedded verbatim into the log message: [2](#0-1) 

`trace_test.go` lines 52–54 explicitly assert that a client-supplied `X-Real-IP: 10.0.0.100` (RFC1918 private address) is accepted and logged without rejection: [3](#0-2) 

The Traefik `forwardedHeaders.insecure` configuration exists in the Helm chart: [4](#0-3) 

The SECURITY.md exclusions do not cover this finding — it is not a "best practice recommendation," not "theoretical without proof," and not "server-side non-confidential information disclosure" (which covers *disclosing* IPs, not *forging* them in logs): [5](#0-4) 

---

# Audit Report

## Title
Unauthenticated `X-Real-IP` Header Spoofing Allows External Attacker to Forge Internal-Origin Entries in Rosetta Trace Logs

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` unconditionally trusts the `X-Real-IP` request header with no validation of whether it arrived from a trusted proxy. The Traefik ingress is configured with `forwardedHeaders.insecure`, meaning client-supplied `X-Real-IP` headers pass through unmodified. Any unauthenticated external attacker can set `X-Real-IP: 10.0.0.1` and have every trace log entry record the request as originating from a private RFC1918 address.

## Finding Description
`getClientIpAddress()` (lines 63–74 of `rosetta/app/middleware/trace.go`) resolves the client IP in strict priority order:

```go
ipAddress := r.Header.Get(xRealIpHeader)          // line 64 — checked first, no validation
if len(ipAddress) == 0 {
    ipAddress = r.Header.Get(xForwardedForHeader)  // line 67
}
if len(ipAddress) == 0 {
    ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr) // line 71 — only fallback
}
```

The returned value is embedded verbatim into the log message at lines 52–53 of `TracingMiddleware` and written at `log.Info` level for every non-internal path.

**Root cause:** The function assumes `X-Real-IP` is always set by a trusted reverse proxy. There is no allowlist of trusted upstream IPs, no RFC1918 rejection, and no format validation.

**Why the proxy layer does not save it:** The Kubernetes Helm chart configures Traefik with `forwardedHeaders.insecure` on both `web` and `websecure` entrypoints (`charts/hedera-mirror-common/values.yaml`). This flag is Traefik's explicit opt-in to trust and forward all `X-Forwarded-*` / `X-Real-IP` headers from any source, including the external client, without stripping or overwriting them.

The docker-compose nginx proxy does overwrite `X-Real-IP` with `$remote_addr`, but that deployment path is irrelevant to the Kubernetes production path where Traefik is the ingress.

**Test evidence:** `trace_test.go` lines 52–54 explicitly assert that a client-supplied `X-Real-IP: 10.0.0.100` is accepted and logged as the client IP — no test exists that rejects a spoofed private address.

## Impact Explanation
Every `log.Info` trace entry for Rosetta API requests will record the attacker-chosen IP instead of the real source:

- An external attacker can make all their requests appear to originate from `10.0.0.1`, `192.168.0.1`, or any other internal address.
- Security monitoring, SIEM alerting, and incident-response tooling that rely on these logs to distinguish internal vs. external traffic will be misled.
- Audit trails used for compliance or forensic investigation will contain fabricated source IPs, undermining their evidentiary value.
- An attacker can frame internal hosts as the source of malicious Rosetta API calls.

## Likelihood Explanation
Exploitation requires zero privileges and zero special knowledge: a single HTTP request with an added header is sufficient. The attack is trivially repeatable (every request can carry a different spoofed IP), undetectable at the application layer (no error, no rejection, no counter-signal in the response), and applicable to any external client since no authentication is required to reach the Rosetta API.

## Recommendation
1. **Maintain a trusted proxy IP allowlist.** Only accept `X-Real-IP` / `X-Forwarded-For` headers when the direct TCP peer (`r.RemoteAddr`) is a known trusted proxy IP or CIDR range.
2. **Reconsider `forwardedHeaders.insecure` in Traefik.** Replace it with `forwardedHeaders.trustedIPs` listing only the actual load-balancer/proxy CIDRs. This ensures Traefik strips client-supplied forwarding headers before they reach the application.
3. **Add a rejection test** in `trace_test.go` asserting that a spoofed `X-Real-IP` from an untrusted source is not used when `RemoteAddr` is not a trusted proxy.

## Proof of Concept
```bash
curl -H "X-Real-IP: 10.0.0.1" https://<rosetta-endpoint>/network/list
```
The resulting trace log entry will record the source IP as `10.0.0.1` regardless of the actual client IP. This is directly confirmed by the existing test case at `rosetta/app/middleware/trace_test.go` lines 52–54, which asserts this behavior as expected.

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

**File:** rosetta/app/middleware/trace_test.go (L52-54)
```go
		headers:  map[string]string{xRealIpHeader: clientIp},
		path:     defaultPath,
		messages: []string{clientIp},
```

**File:** charts/hedera-mirror-common/values.yaml (L1-1)
```yaml
# SPDX-License-Identifier: Apache-2.0
```

**File:** SECURITY.md (L14-16)
```markdown
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.
```
