### Title
Unbounded `X-Real-IP` Header Value Causes Log Amplification / Resource Exhaustion in `TracingMiddleware`

### Summary
`getClientIpAddress()` reads the `X-Real-IP` (or `X-Forwarded-For`) header with no length validation and returns the raw value, which is then embedded in every log message via `fmt.Sprintf`. Because the Go HTTP server's default `MaxHeaderBytes` is 1MB and no explicit limit is set, an attacker who can reach the service directly can send headers up to ~1MB per request, causing each log line to be proportionally large and driving up log I/O, memory allocation, and CPU overhead at scale.

### Finding Description
In `rosetta/app/middleware/trace.go`, `getClientIpAddress()` performs only an empty-string check before returning the header value:

```go
// lines 63-74
func getClientIpAddress(r *http.Request) string {
    ipAddress := r.Header.Get(xRealIpHeader)       // no length cap
    if len(ipAddress) == 0 {
        ipAddress = r.Header.Get(xForwardedForHeader)
    }
    if len(ipAddress) == 0 {
        ipAddress, _, _ = net.SplitHostPort(r.RemoteAddr)
    }
    return ipAddress
}
``` [1](#0-0) 

The returned value is immediately interpolated into a log message:

```go
// lines 52-53
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)
``` [2](#0-1) 

The `http.Server` in `main.go` sets no `MaxHeaderBytes`, so Go's default of **1 048 576 bytes (1 MB)** applies: [3](#0-2) 

Root cause: the code assumes the header contains a short IP address string. There is no upper-bound check, no IP-format validation, and no trusted-proxy guard.

### Impact Explanation
Each request with a ~1 MB `X-Real-IP` header causes:
- Allocation and formatting of a ~1 MB log string per request.
- That string written to stdout (log sink) on every non-internal path (`log.Info`).

At modest concurrency (e.g., 100 req/s with 8 KB headers each = 800 KB/s extra log throughput; with 1 MB headers = 100 MB/s), log I/O, memory GC pressure, and CPU time for string formatting increase substantially — well above the 30% threshold stated in scope. Persistent flooding can exhaust disk space if logs are persisted, or saturate stdout pipelines.

### Likelihood Explanation
- **Direct exposure**: The Rosetta API is a node-level service. Operators sometimes expose it directly on a port without a reverse proxy (especially in development/testnet). In that case, any unauthenticated HTTP client can set arbitrary headers.
- **Proxy pass-through**: Some nginx/HAProxy configurations forward the client-supplied `X-Real-IP` header rather than overwriting it, leaving the attack surface open even behind a proxy.
- No authentication is required; the attack is trivially scriptable with `curl` or any HTTP client.
- It is repeatable and stateless — each request is independent.

### Recommendation
1. **Validate/truncate the header value** in `getClientIpAddress()` before returning it — accept only strings that parse as a valid IP address (use `net.ParseIP`), and fall back to `RemoteAddr` on failure:
   ```go
   if ip := net.ParseIP(strings.TrimSpace(ipAddress)); ip != nil {
       return ip.String()
   }
   ```
2. **Set `MaxHeaderBytes`** explicitly on the `http.Server` to a small value (e.g., 8 KB) to limit the attack surface at the transport layer.
3. **Add a trusted-proxy check**: only honour `X-Real-IP` / `X-Forwarded-For` when the connection originates from a known proxy CIDR.

### Proof of Concept
```bash
# Generate an 8 KB fake IP string
FAKE_IP=$(python3 -c "print('A' * 8192)")

# Send 1000 requests in parallel; observe log volume spike
for i in $(seq 1 1000); do
  curl -s -o /dev/null \
    -H "X-Real-IP: $FAKE_IP" \
    http://<rosetta-host>:<port>/network/list \
    -X POST -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
done
wait
# Each log line will contain the 8 KB string; monitor log file growth / memory usage
```

Each log entry produced by `TracingMiddleware` will be ~8 KB (or up to ~1 MB with Go's default limit) instead of the normal ~80 bytes, multiplying log I/O by up to ~100–12 000×.

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
