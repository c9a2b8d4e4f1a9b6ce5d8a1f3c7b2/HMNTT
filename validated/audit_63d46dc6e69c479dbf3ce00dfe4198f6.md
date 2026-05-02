All code references have been verified against the actual repository. Here is my assessment:

---

Audit Report

## Title
Unauthenticated IP Spoofing via Unvalidated `X-Real-IP` Header in `getClientIpAddress()` Enables Audit Log Manipulation

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` unconditionally trusts the client-supplied `X-Real-IP` and `X-Forwarded-For` headers with no validation, sanitization, or loopback-address rejection. Because the Rosetta container simultaneously exposes port 5700 directly on the host (bypassing the nginx reverse proxy), an attacker can inject arbitrary IP values — including loopback addresses — causing all their requests to be logged under a spoofed identity.

## Finding Description
The vulnerable function is `getClientIpAddress()` at `rosetta/app/middleware/trace.go` lines 63–74:

```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)          // blindly trusted

    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader) // also blindly trusted
    }

    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }

    return ipAddress
}
``` [1](#0-0) 

There is no call to `net.ParseIP()`, no loopback rejection, and no allowlist of trusted upstream proxy addresses. The returned value is used directly in `TracingMiddleware` to emit the access log line: [2](#0-1) 

The nginx proxy does overwrite `X-Real-IP` with `$$remote_addr` for traffic it handles: [3](#0-2) 

However, the Rosetta container simultaneously binds port 5700 directly to the host: [4](#0-3) 

Any client connecting to port 5700 directly bypasses nginx entirely, and the application accepts whatever `X-Real-IP` value the client supplies.

## Impact Explanation
`TracingMiddleware` is the sole mechanism for recording the source IP of requests to the Rosetta API. By supplying `X-Real-IP: ::1` (or `127.0.0.1`, `0:0:0:0:0:0:0:1`), an attacker causes every one of their requests to be logged as originating from localhost. This corrupts the audit trail for all Rosetta API activity originating from that attacker, defeating log-based intrusion detection, IP-based alerting, and forensic investigation. The multiple valid string representations of the IPv6 loopback address additionally confuse log parsers that perform exact-string matching rather than normalized IP comparison.

## Likelihood Explanation
The precondition — reaching port 5700 directly — is satisfied by default in the `docker-compose` deployment, where port 5700 is bound to `0.0.0.0`. No credentials, tokens, or special network position are required. The attack requires only a single HTTP request with one crafted header and is fully repeatable. Note that the rosetta service is set to `replicas: 0` by default (disabled), but the port mapping is present and the vulnerability is active whenever the service is enabled. [5](#0-4) 

## Recommendation
1. **Validate and reject loopback values**: In `getClientIpAddress()`, parse the header value with `net.ParseIP()` and reject any address that is a loopback (`ip.IsLoopback()`), unspecified, or otherwise non-routable before trusting it.
2. **Restrict direct port exposure**: Remove or firewall the `5700:5700` host port binding so that the Rosetta service is only reachable through the nginx reverse proxy, which already overwrites `X-Real-IP` with the real remote address.
3. **Trusted-proxy allowlist**: Only honour `X-Real-IP` / `X-Forwarded-For` when the TCP-level `r.RemoteAddr` belongs to a known, trusted proxy CIDR range.

## Proof of Concept
```bash
# Connect directly to the exposed Rosetta port, bypassing nginx
curl -s -X POST http://<host>:5700/network/list \
  -H "Content-Type: application/json" \
  -H "X-Real-IP: ::1" \
  -d '{"metadata":{}}'
```
The application log will record the request as:
```
level=info msg="::1 POST /network/list (200) in 3ms"
```
The attacker's real IP never appears in any log entry.

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

**File:** docker-compose.yml (L143-151)
```yaml
    deploy:
      replicas: 0
    environment:
      HIERO_MIRROR_ROSETTA_API_CONFIG: /usr/etc/hiero/application.yml
      HIERO_MIRROR_ROSETTA_DB_HOST: db
    image: gcr.io/mirrornode/hedera-mirror-rosetta:0.155.0-SNAPSHOT
    pull_policy: always
    ports:
      - 5700:5700
```

**File:** docker-compose.yml (L204-204)
```yaml
        proxy_set_header X-Real-IP $$remote_addr;
```
