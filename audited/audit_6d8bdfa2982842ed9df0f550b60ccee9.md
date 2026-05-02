### Title
Unbounded `request.Method` Logged in `TracingMiddleware` Enables Log-Amplification DoS

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` embeds `request.Method` directly into a log message via `fmt.Sprintf` with no length validation or truncation. Go's `net/http` server imposes no per-field limit on the HTTP method — only the aggregate `MaxHeaderBytes` ceiling (default 1 MiB) — so an unauthenticated attacker can craft requests whose method string is nearly 1 MiB, producing a ~1 MiB log entry per request and driving log I/O and memory overhead far above the 30 % threshold.

### Finding Description
**Exact location:** `rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 52–53:

```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

`request.Method` is taken verbatim from the parsed HTTP request and concatenated into `message` with no `len()` guard, no truncation, and no sanitisation.

**Root cause / failed assumption:** The code assumes the HTTP method will always be a short, well-known token (GET, POST, …). Go's `net/http` parser enforces only that the method is a valid RFC 7230 token (all characters must be `!#$%&'*+-.^_|~` or alphanumeric). A string such as `AAAA…AAAA` (up to ~1 MiB of uppercase letters) satisfies that constraint and is handed to the handler unchanged.

**Server configuration** (`rosetta/main.go`, lines 220–227) sets `ReadHeaderTimeout`, `ReadTimeout`, `IdleTimeout`, and `WriteTimeout` but does **not** override `MaxHeaderBytes`, leaving it at Go's default of 1,048,576 bytes (1 MiB). The entire request line (method + space + URL + space + HTTP version + CRLF) counts against this budget, so the method alone can be ~1 MiB minus a few bytes.

**Middleware chain** (`rosetta/main.go`, lines 217–219):
```
corsMiddleware → tracingMiddleware → metricsMiddleware → router
```
`TracingMiddleware` calls `inner.ServeHTTP(…)` **before** it builds and emits the log message (line 50 precedes lines 52–58). Even if the inner Rosetta SDK asserter rejects the request with 400, the log line is still written with the full oversized method string.

### Impact Explanation
Each crafted request produces a log entry of up to ~1 MiB. At a modest rate of 100 requests/second (easily achievable from a single host), the logging subsystem must handle ~100 MiB/s of log I/O. The `fmt.Sprintf` call also allocates a new string of that size on the heap for every request, increasing GC pressure and memory consumption. Both effects comfortably exceed the 30 % resource-increase threshold without any brute-force volume requirement. Log rotation and disk I/O can become bottlenecks, and in containerised deployments log-driver back-pressure can stall the entire process.

### Likelihood Explanation
The Rosetta API is a public-facing HTTP service (default port 5700). No authentication is required to send an HTTP request. The attacker needs only a TCP connection and the ability to craft a raw HTTP request line with a long method token — achievable with `curl`, `netcat`, or any HTTP library. The attack is repeatable, stateless, and requires no knowledge of the application's business logic.

### Recommendation
1. **Truncate `request.Method` before logging.** Add a constant (e.g., `maxMethodLen = 16`) and truncate:
   ```go
   method := request.Method
   if len(method) > maxMethodLen {
       method = method[:maxMethodLen]
   }
   message := fmt.Sprintf("%s %s %s (%d) in %s",
       clientIpAddress, method, path, ...)
   ```
2. **Set `MaxHeaderBytes` explicitly** on the `http.Server` in `rosetta/main.go` to a value appropriate for the Rosetta API (e.g., 8 KiB), reducing the maximum method size the parser will accept.
3. Apply the same truncation to `path` (`request.URL.RequestURI()`) and `clientIpAddress` (from `X-Forwarded-For` / `X-Real-IP`), which share the same unbounded-logging pattern.

### Proof of Concept
```bash
# Generate a ~900 KB method string of valid token characters
METHOD=$(python3 -c "print('A' * 921600)")

# Send the request to the Rosetta server
printf "%s / HTTP/1.1\r\nHost: target:5700\r\nContent-Length: 0\r\n\r\n" "$METHOD" \
  | nc target 5700

# Observe the server log: a single ~900 KB Info-level line is emitted.
# Repeat at 100 req/s to drive log I/O above 90 MB/s.
```
The server will respond 400 or 405 (method not allowed by the Rosetta SDK asserter), but the oversized log entry is written regardless, because `TracingMiddleware` logs **after** `inner.ServeHTTP` returns. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L52-53)
```go
		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
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
