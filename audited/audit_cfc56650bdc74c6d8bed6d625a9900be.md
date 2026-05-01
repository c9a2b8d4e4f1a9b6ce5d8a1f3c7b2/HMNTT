### Title
Unbounded `X-Forwarded-For` Header Logged Verbatim Enables Log-Amplification DoS

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` accepts the full, unvalidated value of the `X-Forwarded-For` header and returns it as `ipAddress`. `TracingMiddleware` then embeds this string into a `fmt.Sprintf`-constructed message and writes it to the log via `log.Info` on every non-internal request. Because Go's `http.Server` is configured without an explicit `MaxHeaderBytes`, the default cap is 1 MB per request, meaning each request can force ~2–3 MB of heap allocation and ~1 MB of synchronous log I/O with zero authentication required.

### Finding Description
**Exact code path:**

- `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74: the function reads `r.Header.Get(xForwardedForHeader)` and returns the raw string with no length check, no IP-count limit, and no format validation.
- Lines 52–53: the returned string is interpolated directly into a `fmt.Sprintf` call, allocating a new heap string proportional to the header length.
- Lines 55–59: `log.Info(message)` is called for every request whose path is not in `internalPaths`, writing the full string to stdout synchronously.
- `rosetta/main.go`, lines 220–227: the `http.Server` struct sets `ReadHeaderTimeout`, `ReadTimeout`, etc., but **never sets `MaxHeaderBytes`**, so Go's default of `1 << 20` (1,048,576 bytes) applies.

**Root cause:** The code assumes the `X-Forwarded-For` value is a short, well-formed IP address. It is attacker-controlled and subject to no sanitisation before being stored and logged.

**Why existing checks fail:**
- `ReadHeaderTimeout` limits *time* to send headers, not their *size*; a fast connection can deliver a 1 MB header well within any reasonable timeout.
- The 1 MB `MaxHeaderBytes` default is a ceiling, not a mitigation — 1 MB per request is the attack payload.
- There is no rate-limiting middleware anywhere in the chain (`MetricsMiddleware` → `TracingMiddleware` → `CorsMiddleware`).

### Impact Explanation
Per request an attacker forces: one ~1 MB heap string from `r.Header.Get`, one ~1 MB heap string from `fmt.Sprintf`, and one synchronous `log.Info` write of ~1 MB to stdout. At modest concurrency (e.g., 50 parallel connections each sending ~20 req/s) this produces ~1 GB/s of log I/O and continuous GC pressure from short-lived multi-MB allocations. CPU time shifts from legitimate request processing to GC and I/O, easily exceeding the 30 % resource-consumption threshold. Log storage can also be exhausted rapidly.

### Likelihood Explanation
No authentication, no special network position, and no prior knowledge of the application is required. Any internet-reachable instance can be targeted. The attack is trivially scriptable with `curl` or any HTTP load tool, is repeatable indefinitely, and leaves no persistent state on the attacker's side.

### Recommendation
1. **Truncate or validate in `getClientIpAddress()`**: extract only the first token before the first comma (the leftmost client IP) and enforce a maximum length (e.g., 45 characters for IPv6):
   ```go
   // rosetta/app/middleware/trace.go, getClientIpAddress()
   ip := r.Header.Get(xForwardedForHeader)
   if idx := strings.IndexByte(ip, ','); idx != -1 {
       ip = ip[:idx]
   }
   ip = strings.TrimSpace(ip)
   if len(ip) > 45 {
       ip = ip[:45]
   }
   ```
2. **Set `MaxHeaderBytes` explicitly** in `main.go` to a small value (e.g., 8 KB) appropriate for the Rosetta API.
3. **Add rate limiting** middleware before `TracingMiddleware`.

### Proof of Concept
```bash
# Build a 1 MB X-Forwarded-For value (~65 000 fake IPs)
PAYLOAD=$(python3 -c "print(','.join(['1.2.3.4']*65000))")

# Fire 50 concurrent streams of requests
for i in $(seq 1 50); do
  while true; do
    curl -s -o /dev/null \
      -H "X-Forwarded-For: $PAYLOAD" \
      http://<rosetta-host>:<port>/network/list \
      -X POST -H "Content-Type: application/json" \
      -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"}}' &
  done &
done
```
Observe: log output rate spikes to hundreds of MB/s, heap usage climbs continuously, and GC pause frequency increases — all attributable to the unbounded header being logged verbatim on every request. [1](#0-0) [2](#0-1) [3](#0-2)

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
