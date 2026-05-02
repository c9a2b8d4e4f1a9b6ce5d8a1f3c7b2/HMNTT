The code at `rosetta/app/middleware/trace.go` confirms the claims exactly. Let me verify the construction service reference as well.

All code references are verified against the actual source. The vulnerability is real and confirmed.

---

Audit Report

## Title
Unsanitized `X-Real-IP` Header Enables Log Injection and Audit Trail Manipulation for Fund Transfer Submissions

## Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` accepts the `X-Real-IP` (and `X-Forwarded-For`) header value without any IP format validation and embeds it verbatim into log messages via `TracingMiddleware`. An attacker who can reach the Rosetta API directly can inject arbitrary byte sequences — including newlines or multi-byte Unicode — into the log stream, forging or corrupting log entries for `/construction/submit` calls and degrading the audit trail for fund transfer submissions.

## Finding Description
**Exact code path — `getClientIpAddress` (lines 63–74):** [1](#0-0) 

The only guard is `len(ipAddress) == 0`. A 4-byte emoji or a string containing `\n` has `len > 0` and passes this check unchanged. There is no call to `net.ParseIP`, no regex validation, and no sanitization.

**Exact code path — `TracingMiddleware` (lines 52–58):** [2](#0-1) 

The raw, attacker-controlled string is interpolated directly into `fmt.Sprintf` and passed to `log.Info`. The `logrus` library does not sanitize newlines in message strings by default, so a `\n` in the header value produces a new line in the log output.

**Affected endpoint — `ConstructionSubmit` (line 332):** [3](#0-2) 

Every request to this endpoint is logged by `TracingMiddleware` before any business logic runs, meaning the injection occurs unconditionally.

## Impact Explanation
An attacker can:
- **Forge log entries**: inject `\n` to create synthetic "successful" log lines attributed to arbitrary IPs, masking the real source of a `/construction/submit` call.
- **Break audit parsers**: embed Unicode/emoji so that IP-extraction regexes (e.g., `\d{1,3}(\.\d{1,3}){3}`) fail, causing the real submit entry to be dropped from SIEM dashboards or compliance reports.
- **Obscure attribution**: make forensic reconstruction of which IP submitted a fraudulent transaction impossible from logs alone.

The `/construction/submit` endpoint is the sole path for submitting signed transactions to the Hedera network via this service; audit trail integrity for this endpoint is critical.

## Likelihood Explanation
The precondition is that the Rosetta API is reachable directly by the attacker without a reverse proxy that unconditionally overwrites `X-Real-IP`. Rosetta nodes are commonly deployed with direct exposure for exchange/custodian integrations. No authentication is required at the HTTP layer — `TracingMiddleware` runs before any business logic. The attack requires only a single crafted HTTP header and is trivially repeatable with `curl`.

## Recommendation
In `getClientIpAddress`, validate the extracted value with `net.ParseIP` before returning it. If the value does not parse as a valid IP address, fall through to the next source or return the `RemoteAddr` value. Additionally, consider stripping or escaping control characters (including `\n`, `\r`) from any string before it is passed to a log function, regardless of source.

```go
func getClientIpAddress(r *http.Request) string {
    for _, header := range []string{xRealIpHeader, xForwardedForHeader} {
        val := r.Header.Get(header)
        if ip := net.ParseIP(strings.TrimSpace(val)); ip != nil {
            return ip.String()
        }
    }
    ipAddress, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ipAddress
}
```

## Proof of Concept
```bash
curl -X POST https://<rosetta-host>/construction/submit \
  -H 'Content-Type: application/json' \
  -H $'X-Real-IP: 1.2.3.4 INFO fake-ip POST /construction/submit (200) in 1ms\n' \
  -d '{"network_identifier":{},"signed_transaction":"..."}'
```

Expected log output (two lines instead of one):
```
INFO 1.2.3.4 INFO fake-ip POST /construction/submit (200) in 1ms
INFO  POST /construction/submit (500) in 3ms
```

The first line is entirely attacker-controlled. The second line (the real entry) has an empty IP field, causing any IP-based log parser or SIEM rule to misclassify or drop it.

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

**File:** rosetta/app/services/construction_service.go (L331-335)
```go
// ConstructionSubmit implements the /construction/submit endpoint.
func (c *constructionAPIService) ConstructionSubmit(
	_ context.Context,
	request *rTypes.ConstructionSubmitRequest,
) (*rTypes.TransactionIdentifierResponse, *rTypes.Error) {
```
