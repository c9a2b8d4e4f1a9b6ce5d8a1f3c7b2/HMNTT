The code references are accurate. Let me verify the exact line numbers and confirm all claims before rendering a verdict.

The code at `rosetta/app/middleware/trace.go` lines 63–74 is confirmed exactly as described. [1](#0-0) 

`TracingMiddleware` embeds the returned value directly into the log message at lines 52–53 with no sanitization. [2](#0-1) 

The test suite at `trace_test.go` lines 52–58 explicitly asserts that a client-supplied `X-Real-IP` value appears verbatim in the log output, confirming the behavior is intentional and load-bearing. [3](#0-2) 

`SECURITY.md` does not exclude log injection, audit trail poisoning, or IP spoofing via header manipulation from scope. The closest exclusions ("best practice recommendations", "theoretical impacts without proof") do not apply here: the behavior is code-confirmed, trivially reproducible with a single `curl` flag, and the impact (permanent misattribution in structured logs) is concrete and demonstrable. [4](#0-3) 

---

Audit Report

## Title
Unauthenticated IP Spoofing via Unvalidated `X-Real-IP` / `X-Forwarded-For` Headers Enables Audit Log Poisoning

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` unconditionally trusts the `X-Real-IP` and `X-Forwarded-For` HTTP headers supplied by any client. There is no trusted-proxy allowlist, no format validation, and `r.RemoteAddr` (the real peer address) is never co-logged. Any unauthenticated caller can permanently misattribute their API activity to an arbitrary IP address in every structured log entry.

## Finding Description
**File:** `rosetta/app/middleware/trace.go`
**Function:** `getClientIpAddress()`, lines 63–74

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)          // blindly trusted

    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)  // blindly trusted
    }

    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr) // only real fallback
    }

    return ipAddress
}
``` [1](#0-0) 

The returned value is immediately embedded in the structured log line by `TracingMiddleware` and emitted at `log.Info` level for every non-internal path:

```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
``` [5](#0-4) 

Three compounding failures:
1. **No trusted-proxy allowlist** — the header is accepted regardless of the TCP connection's origin.
2. **No format/content validation** — the value is used verbatim; it can be any string (`"185.220.101.1"`, `"INTERNAL_ADMIN"`, `"<script>"`).
3. **No secondary correlation** — `r.RemoteAddr` is never logged alongside the header value, so the true source is silently discarded.

The test suite explicitly asserts that a client-supplied `X-Real-IP` value is recorded verbatim, confirming the behavior is intentional: [3](#0-2) 

## Impact Explanation
- **Attacker anonymity:** The attacker's real `RemoteAddr` is never recorded; investigators see only the spoofed address.
- **False attribution / framing:** The attacker can supply another legitimate user's IP, causing all suspicious queries to appear to originate from that user.
- **Audit trail integrity loss:** Post-incident forensics (rate-abuse analysis, data-exfiltration investigations, regulatory audits) rely on these log entries; poisoned entries produce false conclusions.
- **No authentication barrier:** The Rosetta API requires no credentials, making the entire public internet the attack surface.

## Likelihood Explanation
- **Precondition:** Network reachability to the Rosetta port — no account, token, or special privilege required.
- **Trigger:** A single HTTP header added to any request.
- **Repeatability:** 100% — every request with the header is mislogged indefinitely.
- **Detection difficulty:** Because `r.RemoteAddr` is discarded and never co-logged, there is no in-band signal to distinguish a spoofed entry from a legitimate proxy-forwarded one.

## Recommendation
1. **Maintain a trusted-proxy allowlist:** Only honor `X-Real-IP` / `X-Forwarded-For` when `r.RemoteAddr` matches a known trusted proxy CIDR (e.g., configured at startup). For all other connections, fall through directly to `r.RemoteAddr`.
2. **Always co-log `r.RemoteAddr`:** Emit the real TCP peer address alongside the resolved client IP so that spoofed entries can be detected in post-incident review.
3. **Validate header format:** If the header value is used, verify it parses as a valid IP address (`net.ParseIP`) before accepting it; reject or sanitize non-IP strings.
4. **Update the test suite:** Add negative test cases asserting that a header from an untrusted source is ignored in favor of `r.RemoteAddr`.

## Proof of Concept
```bash
# Attribute all requests to a victim's IP address
curl -H "X-Real-IP: 203.0.113.42" http://<rosetta-host>:<port>/network/list

# Every resulting log entry will read:
# level=info msg="203.0.113.42 GET /network/list (200) in Xms"
# The attacker's real IP is never recorded.
```

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

**File:** SECURITY.md (L14-16)
```markdown
- Best practice recommendations.
- Feature requests.
- Impacts on test files and configuration files, unless stated otherwise in the bug bounty program.
```
