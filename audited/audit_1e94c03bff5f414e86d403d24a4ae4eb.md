### Title
Unbounded `X-Forwarded-For` Header Embedded in Log Messages Enables Log-Evasion of Transaction Activity

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` reads the `X-Forwarded-For` (or `X-Real-IP`) header and returns it without any length constraint. The raw value is then interpolated directly into every access-log entry by `TracingMiddleware`. An unauthenticated attacker who reaches the Rosetta API directly can supply a header value up to Go's default 1 MB `MaxHeaderBytes` limit, producing a log line of the same size; most real-world logging back-ends (syslog ≤ 8 KB, journald default 48 KB, many SIEM pipelines) will silently truncate or drop the entry, erasing the method, path, status code, and latency fields that would otherwise record the transaction-submission attempt.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/trace.go` – `getClientIpAddress()` (lines 63–74):
```go
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)   // ← attacker-controlled, unbounded
    }
    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }
    return ipAddress
}
```

`TracingMiddleware` (lines 52–59) then builds and emits the log entry:
```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path,
    tracingResponseWriter.statusCode, time.Since(start))
// clientIpAddress is the first field; if it is 64 KB the rest is beyond any truncation point
log.Info(message)
```

**Root cause:** The only guard on the header value is `len(ipAddress) == 0` (lines 66, 70) — an emptiness check, not a maximum-length check. No sanitisation, truncation, or validation is applied before the value is placed at the start of the log string.

**HTTP server limits:** `rosetta/main.go` lines 220–227 construct the `http.Server` without setting `MaxHeaderBytes`; Go's default is `http.DefaultMaxHeaderBytes = 1 << 20` (1 MB), so a 64 KB header is accepted without error.

**Bypass of nginx proxy:** `docker-compose.yml` line 151 maps `5700:5700` directly to the host, exposing the Rosetta port without requiring the nginx reverse proxy. An attacker who connects directly skips nginx's `large_client_header_buffers` (default 4 × 8 KB) entirely.

**Exploit flow:**
1. Attacker opens a TCP connection to port 5700 directly.
2. Sends `POST /construction/submit` with `X-Forwarded-For: <64 KB random string>` and a valid (or crafted) Rosetta payload.
3. `getClientIpAddress()` returns the 64 KB string; `TracingMiddleware` emits a ~64 KB log line beginning with that string.
4. The logging back-end (syslog, journald, Loki, Splunk forwarder, etc.) truncates the entry at its own limit; the fields `POST /construction/submit (200) in 3ms` are never stored.
5. The transaction submission leaves no auditable trace in the log pipeline.

### Impact Explanation
Every Rosetta API request is logged exclusively through `TracingMiddleware`; there is no secondary audit log for transaction submissions. Successful suppression of log entries for `/construction/submit` calls means that transaction gossip activity — including attempts to submit malformed, duplicate, or adversarial transactions — is invisible to operators and SIEM systems. This directly undermines the auditability guarantee that the tracing middleware is designed to provide, and satisfies the "hiding transaction gossip suppression activity" threat model described in the question.

### Likelihood Explanation
No authentication or network-level restriction is required; port 5700 is exposed on the host by default. The attack requires only a standard HTTP client (e.g., `curl`) and a single request. It is trivially repeatable and automatable. The attacker does not need any credentials, API keys, or prior knowledge of the system beyond the open port.

### Recommendation
1. **Truncate the header value before logging.** In `getClientIpAddress()`, cap the returned string to a safe maximum (e.g., 45 characters covers the longest valid IPv6 address):
   ```go
   const maxIPLength = 45
   if len(ipAddress) > maxIPLength {
       ipAddress = ipAddress[:maxIPLength]
   }
   ```
2. **Use structured logging fields** (logrus `WithField`) so that even if the IP field is large, the other fields (method, path, status) are stored as separate key-value pairs and are not subject to the same truncation.
3. **Set `MaxHeaderBytes`** on the `http.Server` in `rosetta/main.go` to a value appropriate for expected IP header sizes (e.g., 8 KB).
4. **Restrict direct external access** to port 5700; require all traffic to pass through the nginx proxy, which enforces its own header-size limits.

### Proof of Concept
```bash
# Generate a 64 KB string
PAYLOAD=$(python3 -c "print('A' * 65536)")

# Send directly to the exposed Rosetta port (bypassing nginx)
curl -s -X POST http://<rosetta-host>:5700/construction/submit \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: ${PAYLOAD}" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"},"signed_transaction":""}' \
  > /dev/null

# Observe that the corresponding log entry in journald / syslog is either
# absent or truncated to only the IP prefix, with no method/path/status recorded.
# On a system using journald (default 48 KB field limit):
journalctl -u rosetta --since "1 minute ago" | grep "POST /construction/submit"
# Expected: no output — the entry was truncated before the path field.
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```
