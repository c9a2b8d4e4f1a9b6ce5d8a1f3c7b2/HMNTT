### Title
Unbounded `X-Forwarded-For` Header Value Logged Verbatim Causes Log Amplification DoS

### Summary
`getClientIpAddress()` in `rosetta/app/middleware/trace.go` reads the raw `X-Forwarded-For` header value with no length cap or IP-list parsing, storing the entire string as `ipAddress`. `TracingMiddleware` then embeds this value verbatim into a `log.Info` call on every non-internal request. An unauthenticated attacker can craft requests with a header value up to Go's default 1 MB header limit, causing each request to produce a ~1 MB log entry and proportional memory allocation, amplifying I/O and memory overhead far beyond normal per-request cost.

### Finding Description
**Exact code path:**

- `rosetta/app/middleware/trace.go`, `getClientIpAddress()`, lines 63–74:
  ```go
  ipAddress = r.Header.Get(xForwardedForHeader)   // line 67 — raw value, no length check
  ```
  The only guard is `len(ipAddress) == 0` (line 66), which only tests for absence, not size.

- `TracingMiddleware`, lines 52–58:
  ```go
  message := fmt.Sprintf("%s %s %s (%d) in %s",
      clientIpAddress, ...)   // entire multi-KB string interpolated
  log.Info(message)           // written to log on every non-internal request
  ```

**Root cause:** The function assumes `X-Forwarded-For` contains a single IP address. The RFC 7239 / de-facto standard format is a comma-separated list (`client, proxy1, proxy2`). The code never splits on commas, never validates format, and never truncates. The correct client IP is the first token; instead the whole value is used.

**Failed assumption:** The code assumes the header value is a short, well-formed IP string. An attacker controls this header entirely when connecting directly or through a proxy that forwards it.

**HTTP server constraint:** `rosetta/main.go` lines 220–227 construct the `http.Server` without setting `MaxHeaderBytes`, so Go's default of `1 << 20` (1,048,576 bytes) applies. A single `X-Forwarded-For` header can therefore be up to ~1 MB.

**Existing checks reviewed:**
- The Traefik `rateLimit` (average: 10, `sourceCriterion: requestHost`) in `charts/hedera-mirror-rosetta/values.yaml` lines 157–160 is: (a) conditional on `global.middleware && middleware` being enabled — not guaranteed in all deployments; (b) keyed on the `Host` header, which the attacker also controls; (c) even when active, 10 req/s × ~1 MB/req = ~10 MB/s of log I/O from the IP field alone.
- The `inFlightReq: amount: 5` limits concurrency but not header payload size.
- No application-level length check exists anywhere in the middleware chain.

### Impact Explanation
Each crafted request forces: (1) a ~1 MB string allocation for `ipAddress`; (2) a second ~1 MB `fmt.Sprintf` allocation for `message`; (3) a synchronous `log.Info` write of ~1 MB to the log sink (file, stdout, or log aggregator). At 10 req/s (the Traefik rate limit), this is ~10 MB/s of extra log I/O and ~20 MB/s of transient heap allocation per attacker connection, easily exceeding the 30% resource increase threshold. Log storage can be exhausted, log aggregation pipelines can be saturated, and GC pressure increases. The impact is amplified because the Rosetta API is a public blockchain interface with no authentication on any endpoint.

### Likelihood Explanation
The attack requires zero privileges: any HTTP client can set arbitrary headers. The `X-Forwarded-For` header is a standard, well-known header. The exploit is a single `curl` command. It is trivially repeatable and automatable. The Traefik rate-limit mitigation is optional and bypassable via Host-header variation. Direct deployments (without Traefik) have no rate limiting at all.

### Recommendation
In `getClientIpAddress()`, parse only the first token of the `X-Forwarded-For` value and enforce a maximum length:

```go
if len(ipAddress) == 0 {
    xff := r.Header.Get(xForwardedForHeader)
    if idx := strings.IndexByte(xff, ','); idx != -1 {
        xff = xff[:idx]
    }
    ipAddress = strings.TrimSpace(xff)
    // Optional hard cap as defence-in-depth
    if len(ipAddress) > 45 { // max IPv6 length
        ipAddress = ipAddress[:45]
    }
}
```

Additionally, set `MaxHeaderBytes` on the `http.Server` in `rosetta/main.go` to a value appropriate for the API (e.g., 16 KB) to bound total header size at the transport layer.

### Proof of Concept
```bash
# Generate a ~64 KB X-Forwarded-For value (thousands of IPs)
PAYLOAD=$(python3 -c "print(', '.join(f'1.2.3.{i%256}' for i in range(4000)))")

# Send to any Rosetta endpoint (no auth required)
curl -s -o /dev/null \
  -H "X-Forwarded-For: $PAYLOAD" \
  http://<rosetta-host>:<port>/network/list \
  -X POST -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}'

# Observe log output: each entry contains the full ~64 KB IP string
# Repeat in a loop to amplify log I/O and memory pressure
for i in $(seq 1 100); do
  curl -s -o /dev/null -H "X-Forwarded-For: $PAYLOAD" \
    http://<rosetta-host>:<port>/network/list \
    -X POST -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"metadata":{}}' &
done
wait
```

Each iteration produces a log line of ~64 KB (scalable to ~1 MB with Go's default header limit). Sustained over time, this measurably increases log I/O, heap allocation, and GC frequency on the node. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
