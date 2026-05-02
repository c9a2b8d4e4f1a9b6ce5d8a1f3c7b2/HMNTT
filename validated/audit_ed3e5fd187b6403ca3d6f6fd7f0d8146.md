All three critical claims check out against the actual code:

1. `getClientIpAddress()` at lines 63–74 reads `X-Forwarded-For` verbatim with zero sanitization. [1](#0-0) 
2. The raw value is embedded via `fmt.Sprintf` and passed to `log.Info` at lines 52–58. [2](#0-1) 
3. Traefik is configured with `--entryPoints.web.forwardedHeaders.insecure` at lines 643–645, confirming all `X-Forwarded-For` values are passed through unchanged. [3](#0-2) 

The SECURITY.md exclusion for "Reflected plain text injection (e.g. URL parameters, path, etc.)" refers to client-side reflection, not server-side log injection (CWE-117). This finding is server-side log forgery affecting audit trail integrity, which is a distinct vulnerability class not covered by that exclusion. [4](#0-3) 

---

# Audit Report

## Title
Log Injection via Unsanitized `X-Forwarded-For` Header in `getClientIpAddress()`

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` returns the raw `X-Forwarded-For` header value without any validation or character filtering. `TracingMiddleware` embeds this value directly into a logrus log message via `fmt.Sprintf`. Because Traefik is deployed with `--entryPoints.web.forwardedHeaders.insecure`, any external client can supply an arbitrary header value — including newlines, fake log fields, and ANSI escape sequences — which are written verbatim to the log stream.

## Finding Description
**File:** `rosetta/app/middleware/trace.go`

`getClientIpAddress()` (lines 63–74) reads the `X-Forwarded-For` header with no format check, no character allowlist, and no stripping of control characters or newlines:

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)  // raw, unsanitized
    }
    ...
    return ipAddress
}
```

`TracingMiddleware` (lines 52–58) then embeds the value directly into a log message:

```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)
log.Info(message)  // written verbatim
```

**Root cause:** The function assumes the header contains a valid IP address string. There is no format check, no character allowlist, and no stripping of control characters or newlines.

**Failed assumption:** The code assumes a trusted reverse proxy has already validated the `X-Forwarded-For` header. In practice, Traefik is configured with `--entryPoints.web.forwardedHeaders.insecure` (`charts/hedera-mirror-common/values.yaml` lines 643–645), which instructs Traefik to trust and forward all `X-Forwarded-For` headers from all sources without any IP allowlist. The client-supplied value reaches the Go handler unchanged.

## Impact Explanation
- **Log forgery:** An attacker can inject fake log entries that appear to originate from any IP address, for any endpoint, with any HTTP status code and timestamp. SIEM systems or audit tools reconstructing Rosetta transaction history from logs will ingest forged entries, causing misattribution of requests (e.g., attributing a `/block` or `/construction/submit` call to a different IP or time).
- **Log reordering:** By injecting timestamps in the past or future, an attacker can cause log-based timeline reconstruction tools to place fabricated events at arbitrary positions in the transaction history.
- **Terminal escape injection:** Operators viewing live logs in a terminal are exposed to screen-clearing or color-manipulation payloads, potentially hiding real alerts.
- **Severity:** Medium–High. No direct fund theft, but the integrity of the audit trail for the Rosetta API — the primary interface for exchange integrations and block explorers — is compromised.

## Likelihood Explanation
- **No authentication required.** Any HTTP client reachable by the Traefik ingress can send the crafted header.
- **Traefik `forwardedHeaders.insecure` is committed to the production Helm chart** (`charts/hedera-mirror-common/values.yaml` lines 643–645), making this the default deployed configuration.
- **Trivially repeatable** with a single `curl` command.
- The only precondition is network access to the Traefik ingress, which is the public-facing entry point.

## Recommendation
Sanitize the IP address value returned by `getClientIpAddress()` before it is used in any log message. Apply one or both of the following:

1. **Validate format:** After reading the header, verify the value is a valid IP address using `net.ParseIP()`. If it fails validation, fall back to `r.RemoteAddr` or a placeholder like `"unknown"`.
2. **Strip control characters:** At minimum, remove or replace newline characters (`\n`, `\r`) and ANSI escape sequences before embedding the value in any log string.

Example fix for `getClientIpAddress()`:
```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)
    }
    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }
    // Validate it is actually an IP address
    if net.ParseIP(strings.TrimSpace(ipAddress)) == nil {
        ipAddress = "unknown"
    }
    return ipAddress
}
```

Additionally, consider removing `--entryPoints.web.forwardedHeaders.insecure` from the Traefik configuration and replacing it with an explicit `trustedIPs` allowlist scoped to known internal proxy CIDR ranges.

## Proof of Concept
```bash
# Log line injection
curl -H 'X-Forwarded-For: 1.2.3.4\ntime="2024-01-01T00:00:00Z" level=info msg="10.0.0.1 POST /transactions (200) in 2ms"' \
     http://<traefik-ingress>/rosetta/network/list

# ANSI terminal escape injection
curl -H $'X-Forwarded-For: \x1b[2J\x1b[H\x1b[31m[CRITICAL] node compromised\x1b[0m' \
     http://<traefik-ingress>/rosetta/network/list
```

In both cases, Traefik passes the header unchanged (insecure mode), `getClientIpAddress()` returns the multi-line or escape-containing string, `fmt.Sprintf` embeds it, and `log.Info` writes it verbatim to the log stream.

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

**File:** charts/hedera-mirror-common/values.yaml (L643-645)
```yaml
  globalArguments:  # Expose X-Forwarded-For header for tracing
    - --entryPoints.web.forwardedHeaders.insecure
    - --entryPoints.websecure.forwardedHeaders.insecure
```

**File:** SECURITY.md (L33-34)
```markdown
- Reflected plain text injection (e.g. URL parameters, path, etc.).
- This does not exclude reflected HTML injection with or without JavaScript.
```
