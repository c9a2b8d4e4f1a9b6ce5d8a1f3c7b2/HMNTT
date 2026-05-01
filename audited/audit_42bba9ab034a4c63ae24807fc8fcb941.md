### Title
Unbounded Log Amplification via User-Controlled `X-Real-IP` and URL Path in `TracingMiddleware`

### Summary
`TracingMiddleware` unconditionally trusts and embeds the user-supplied `X-Real-IP` header and the full request URI into every `log.Info` call with no rate limiting, no sanitization, and no length cap. An unprivileged attacker can flood the service with requests carrying unique spoofed IPs and unique paths, producing an unbounded stream of distinct log lines that defeat deduplication-based sampling in downstream log aggregators (Loki, Fluentd, Logstash, etc.) and exhaust log storage.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61.

```
clientIpAddress := getClientIpAddress(request)   // line 46 – fully user-controlled
path := request.URL.RequestURI()                  // line 47 – fully user-controlled

message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, ...)   // line 52-53

if internalPaths[path] {
    log.Debug(message)   // line 56
} else {
    log.Info(message)    // line 58  ← always fires for any non-internal path
}
```

`getClientIpAddress` (lines 63–74) reads `X-Real-IP` first, then `X-Forwarded-For`, then `RemoteAddr`. There is **no validation** that the header value matches the actual TCP peer, no length limit, and no allowlist.

**Root cause / failed assumption:** The middleware assumes that log volume is bounded by the number of legitimate clients and paths. It does not account for an adversary who can freely forge both dimensions. Because the log message is a free-form string containing two user-controlled fields, every request with a new `(X-Real-IP, path)` pair produces a **globally unique** log line. Downstream aggregators that implement sampling or rate-limiting by matching on message content or stream labels (e.g., Loki label cardinality, Logstash fingerprint deduplication) cannot collapse these lines.

**Why the only existing check is insufficient:** The `internalPaths` guard (line 55) only demotes `/liveness`, `/metrics`, and `/readiness` to `log.Debug`. Every other path — including completely fabricated ones like `/aaaaaa`, `/aaaaab`, … — is logged at `log.Info`, which is always collected in production.

**No rate limiting exists anywhere in the middleware stack** — confirmed by the absence of any rate-limit, throttle, or connection-limit logic across all files in `rosetta/app/middleware/`.

### Impact Explanation
- **Log storage exhaustion**: at high request rates (trivially achievable with a single `wrk`/`hey` instance), disk or object-store quotas for log data fill up, causing the logging daemon to drop subsequent entries — including legitimate security-relevant ones.
- **High-cardinality stream explosion**: Loki and similar label-based aggregators index each unique `(IP, path)` combination as a separate stream; unbounded cardinality degrades query performance and can crash the ingester.
- **Sampling bypass**: aggregators configured to sample "repeated" messages (e.g., keep 1-in-100 identical lines) receive no repeated lines, so 100 % of attacker-generated noise is retained while legitimate traffic may be dropped under back-pressure.
- Severity matches the stated scope: **medium griefing** — no direct fund loss, but availability of the observability plane is impaired.

### Likelihood Explanation
- **Zero privilege required**: any HTTP client reachable to the Rosetta port can exploit this.
- **Trivially scriptable**: a single shell loop or load-testing tool with a counter-based path and a spoofed `X-Real-IP` header is sufficient.
- **Repeatable indefinitely**: there is no server-side counter, token bucket, or connection cap to exhaust.
- **No detection before impact**: the attack is indistinguishable from legitimate high-traffic until storage or aggregator limits are hit.

### Recommendation
1. **Validate / ignore `X-Real-IP` unless behind a trusted proxy**: only accept the header when the TCP peer IP is in a configured trusted-proxy CIDR; otherwise fall back to `RemoteAddr`.
2. **Cap field lengths** before embedding in log messages (e.g., truncate IP strings to 45 chars, paths to 256 chars).
3. **Add a per-IP or global log-rate limiter** in `TracingMiddleware` using a token-bucket (e.g., `golang.org/x/time/rate`) so that at most N log lines per second are emitted regardless of request volume.
4. **Use structured logging with fixed-cardinality fields** (method, status code) as log labels, and move the free-form path/IP to a non-indexed message body, so aggregators can apply label-based rate limits correctly.

### Proof of Concept

```bash
# Flood with 100 000 unique paths and unique spoofed IPs (no auth required)
for i in $(seq 1 100000); do
  curl -s -o /dev/null \
    -H "X-Real-IP: 10.0.$((i / 256)).$((i % 256))" \
    "http://<rosetta-host>:8082/unique/path/$i" &
done
wait
```

Each iteration produces a distinct `log.Info` line such as:
```
level=info msg="10.0.0.1 GET /unique/path/1 (404) in 1.2ms"
level=info msg="10.0.0.2 GET /unique/path/2 (404) in 1.1ms"
...
```

100 000 unique lines are written with no server-side throttle. Repeat in a tight loop to exhaust log storage or overwhelm the aggregator ingestion pipeline. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/middleware/trace.go (L43-61)
```go
func TracingMiddleware(inner http.Handler) http.Handler {
	return http.HandlerFunc(func(responseWriter http.ResponseWriter, request *http.Request) {
		start := time.Now()
		clientIpAddress := getClientIpAddress(request)
		path := request.URL.RequestURI()
		tracingResponseWriter := newTracingResponseWriter(responseWriter)

		inner.ServeHTTP(tracingResponseWriter, request)

		message := fmt.Sprintf("%s %s %s (%d) in %s",
			clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))

		if internalPaths[path] {
			log.Debug(message)
		} else {
			log.Info(message)
		}
	})
}
```

**File:** rosetta/app/middleware/trace.go (L63-75)
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
}
```
