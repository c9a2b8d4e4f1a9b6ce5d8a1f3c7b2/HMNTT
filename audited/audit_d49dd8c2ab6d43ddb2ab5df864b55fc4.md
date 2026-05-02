### Title
IP Address Spoofing via Empty `X-Real-IP`/`X-Forwarded-For` Headers Enables Attacker Log Evasion in Rosetta Tracing Middleware

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` uses `len(ipAddress) == 0` to detect missing headers, but Go's `r.Header.Get()` returns `""` for both absent headers and headers explicitly set to an empty string. Combined with the Traefik deployment configured with `--entryPoints.web.forwardedHeaders.insecure` (which passes all client-supplied headers through without stripping), an unprivileged attacker can send `X-Real-IP: ` and `X-Forwarded-For: ` (both empty) to force fallback to `r.RemoteAddr`, which resolves to Traefik's internal pod IP rather than the attacker's real IP. This allows the attacker to erase their identity from access logs.

### Finding Description

**Exact code path** — `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74:

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)       // returns "" for empty OR absent

    if len(ipAddress) == 0 {                        // true for both cases — no distinction
        ipAddress = r.Header.Get(xForwardedForHeader)
    }

    if len(ipAddress) == 0 {                        // again, true for empty string
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)  // falls back to proxy pod IP
    }

    return ipAddress
}
``` [1](#0-0) 

**Root cause**: Go's `net/http` `Header.Get()` returns `""` for both a missing header and a header present with an empty value. The guard `len(ipAddress) == 0` cannot distinguish between the two cases, so an attacker who explicitly sends `X-Real-IP: ` (empty value) triggers the same fallback as if the header were absent.

**Why the deployment makes this reachable**: The Helm chart configures Traefik with `--entryPoints.web.forwardedHeaders.insecure` and `--entryPoints.websecure.forwardedHeaders.insecure`: [2](#0-1) 

This flag instructs Traefik to trust forwarded headers from **all** sources with no IP allowlist, meaning client-supplied `X-Real-IP` and `X-Forwarded-For` values are forwarded to the rosetta service verbatim — including empty-string values.

**Exploit flow**:
1. Attacker sends HTTP request directly through Traefik with headers `X-Real-IP: ` and `X-Forwarded-For: ` (both present but empty).
2. Traefik, configured with `forwardedHeaders.insecure`, passes both headers through unchanged.
3. `r.Header.Get("X-Real-IP")` returns `""` → `len("") == 0` → falls through.
4. `r.Header.Get("X-Forwarded-For")` returns `""` → `len("") == 0` → falls through.
5. `net.SplitHostPort(r.RemoteAddr)` is called; `r.RemoteAddr` is Traefik's internal pod IP (e.g., `10.x.x.x`), not the attacker's external IP.
6. The log entry records Traefik's pod IP as the "client", completely obscuring the attacker's identity.

**Broader variant** (same root cause): The attacker can also set `X-Real-IP: <any_arbitrary_ip>` and it will be logged verbatim as the client IP, since there is no validation that the value is a legitimate IP or that the header came from a trusted proxy.

**Existing checks reviewed and shown insufficient**: The only guard is `len(ipAddress) == 0`. There is no:
- Distinction between absent vs. explicitly-empty headers
- Validation that `ipAddress` is a syntactically valid IP address
- Trusted-proxy allowlist to restrict which sources may set these headers
- Header stripping at the application layer

### Impact Explanation

The rosetta tracing middleware is the sole mechanism for recording client IP addresses in access logs. An attacker performing a sustained attack (e.g., flooding the Rosetta API to suppress transaction gossip, or probing for vulnerabilities) can render all log-based forensics and IP-based blocking ineffective. Security teams monitoring logs for anomalous IPs will see only Traefik's internal pod IP, making it impossible to identify, attribute, or block the real attacker. This is a log-integrity / audit-trail failure with direct operational security impact.

### Likelihood Explanation

**Preconditions**: The attacker needs only HTTP access to the rosetta endpoint through Traefik — no credentials, no special privileges, no prior knowledge beyond the public API. The `forwardedHeaders.insecure` Traefik configuration is present in the shipped Helm chart and is the default deployment posture. Any external user of the Rosetta API can trigger this. The attack is trivially repeatable with a single `curl` command.

### Recommendation

1. **Distinguish absent from empty headers**: Replace `len(ipAddress) == 0` with `ipAddress == ""` (same behavior in Go, but document intent) and additionally check whether the header was actually present using `r.Header.Values(xRealIpHeader)` — if the slice is non-empty but the value is `""`, treat it as a spoofing attempt and skip to `RemoteAddr` directly.

2. **Validate the extracted IP**: After extraction, parse with `net.ParseIP(ipAddress)` and fall back to `RemoteAddr` if parsing fails.

3. **Remove `forwardedHeaders.insecure` from Traefik**: Replace with an explicit trusted-proxy CIDR allowlist using `--entryPoints.web.forwardedHeaders.trustedIPs=<pod_cidr>`. This ensures only Traefik itself (not external clients) can set `X-Real-IP`/`X-Forwarded-For`.

4. **Strip client-supplied proxy headers at the Traefik layer**: Configure Traefik to remove `X-Real-IP` and `X-Forwarded-For` from inbound client requests before forwarding, then re-inject them with the verified `$remote_addr`.

### Proof of Concept

```bash
# Attacker sends both headers as empty strings through Traefik
curl -H "X-Real-IP: " -H "X-Forwarded-For: " \
     https://<rosetta-endpoint>/network/list

# Expected log entry (before fix):
# 10.x.x.x GET /network/list (200) in 5ms
# (10.x.x.x is Traefik's pod IP, not the attacker's IP)

# For comparison, without the empty headers:
curl https://<rosetta-endpoint>/network/list
# Log entry would show attacker's real IP (or Traefik's IP if no X-Real-IP is set by Traefik)

# Arbitrary IP injection variant:
curl -H "X-Real-IP: 8.8.8.8" https://<rosetta-endpoint>/network/list
# Log entry: 8.8.8.8 GET /network/list (200) in 5ms
# (completely fabricated IP logged as the client)
```

### Citations

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

**File:** charts/hedera-mirror-common/values.yaml (L643-645)
```yaml
  globalArguments:  # Expose X-Forwarded-For header for tracing
    - --entryPoints.web.forwardedHeaders.insecure
    - --entryPoints.websecure.forwardedHeaders.insecure
```
