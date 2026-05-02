### Title
Unauthenticated Replay Flood on `/construction/submit` Enables Resource Exhaustion and Transaction Submission Starvation

### Summary
The `ConstructionSubmit` function in `rosetta/app/services/construction_service.go` accepts any valid signed transaction and unconditionally forwards it to a Hiero consensus node via `hiero.TransactionExecute()`, with no rate limiting, no per-transaction deduplication cache, and no concurrency cap. An unprivileged attacker can replay the same signed transaction in a tight loop, causing the server to make unbounded outbound gRPC calls to consensus nodes for every request, exhausting the SDK client's connection resources and starving legitimate submissions.

### Finding Description

**Exact code path:**

`rosetta/main.go` builds the middleware chain as:

```
MetricsMiddleware → TracingMiddleware → CorsMiddleware → router
``` [1](#0-0) 

The three middleware layers (`metrics.go`, `trace.go`, `health.go`) provide only observability and CORS — none implement rate limiting or request throttling. [2](#0-1) [3](#0-2) 

`ConstructionSubmit` performs only three checks before executing the transaction:

1. `IsOnline()` — rejects offline-mode calls only
2. `unmarshallTransactionFromHexString` — validates hex encoding and protobuf structure
3. `isSupportedTransactionType` — allows only `AccountCreateTransaction` or `TransferTransaction`

None of these prevent the same signed transaction from being submitted repeatedly:

```go
func (c *constructionAPIService) ConstructionSubmit(
    _ context.Context,
    request *rTypes.ConstructionSubmitRequest,
) (*rTypes.TransactionIdentifierResponse, *rTypes.Error) {
    if !c.IsOnline() { ... }
    transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
    ...
    _, err = hiero.TransactionExecute(transaction, c.sdkClient)
    ...
}
``` [4](#0-3) 

The SDK client has auto-retry explicitly disabled (`SetMaxAttempts(1)`), meaning each HTTP request to `/construction/submit` results in exactly one synchronous gRPC call to a consensus node — no batching, no deduplication, no backpressure. [5](#0-4) 

**Root cause:** The application layer has no deduplication cache keyed on transaction ID/hash, no per-IP or global request rate limiter, and no concurrency semaphore on the submit path. The assumption that callers will submit each signed transaction only once is never enforced.

### Impact Explanation

Each replayed request causes the server to:
- Deserialize the transaction bytes
- Compute the transaction hash
- Open or reuse a gRPC connection to a Hiero consensus node and block waiting for a response

The Hiero network will reject duplicates with `DUPLICATE_TRANSACTION` (transactions share a `transactionId = accountId + validStart`, valid for up to 180 seconds as set by `maxValidDurationSeconds`), but the mirror node server has already consumed a goroutine and a consensus-node connection slot for each request. A flood of replays can:

1. Exhaust the `sdkClient` connection pool, causing legitimate `TransactionExecute` calls to queue or fail
2. Saturate server goroutines, degrading all Rosetta API endpoints
3. Fill server logs, masking real errors

Severity: **Medium–High** (availability impact on the Rosetta submission path; no confidentiality or integrity impact). [6](#0-5) 

### Likelihood Explanation

**Preconditions:** None beyond network access. The attacker constructs a single valid `TransferTransaction` or `AccountCreateTransaction`, signs it, hex-encodes it, and has a reusable payload. No credentials, API keys, or privileged access are required. The endpoint is publicly reachable in online mode.

**Feasibility:** A single machine sending HTTP POST requests in a loop (e.g., with `curl`, `ab`, or a trivial script) can sustain thousands of requests per second. The 180-second transaction validity window gives the attacker a sustained replay window before needing a new transaction.

**Repeatability:** The attack is trivially repeatable and scriptable. The attacker does not need to intercept anyone else's transaction; they can generate their own.

### Recommendation

1. **Application-layer rate limiting:** Add a per-IP (and optionally global) rate-limiting middleware on `/construction/submit`, e.g., using `golang.org/x/time/rate` or a token-bucket middleware, inserted into the chain in `main.go` before the router.

2. **Transaction deduplication cache:** Maintain a short-lived in-memory cache (TTL = `maxValidDurationSeconds` = 180 s) keyed on the transaction hash or transaction ID. Reject with HTTP 409 or a Rosetta error if the same transaction has already been submitted within its validity window. [7](#0-6) 

3. **Concurrency cap:** Add a semaphore or `golang.org/x/sync/semaphore` around `hiero.TransactionExecute` to bound the number of simultaneous outbound gRPC calls.

4. **Infrastructure layer:** Deploy a reverse proxy (e.g., nginx, Envoy) in front of the Rosetta server with connection-rate and request-rate limits as a defense-in-depth measure.

### Proof of Concept

```bash
# 1. Build a valid signed transaction (e.g., via /construction/payloads + /construction/combine)
SIGNED_TX="0x<hex-encoded signed TransferTransaction>"

# 2. Replay it in a tight loop from a single unprivileged client
for i in $(seq 1 10000); do
  curl -s -X POST http://<rosetta-host>:<port>/construction/submit \
    -H "Content-Type: application/json" \
    -d "{\"network_identifier\":{\"blockchain\":\"Hiero\",\"network\":\"testnet\"},\"signed_transaction\":\"$SIGNED_TX\"}" &
done
wait

# Expected result:
# - First request: HTTP 200, transaction hash returned
# - All subsequent requests: HTTP 200 with ErrTransactionSubmissionFailed (DUPLICATE_TRANSACTION from network)
#   BUT each request still consumed a server goroutine + gRPC call to a consensus node
# - Legitimate /construction/submit calls from other users experience increased latency or failure
#   due to connection pool exhaustion on the sdkClient
```

### Citations

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```

**File:** rosetta/app/middleware/metrics.go (L76-84)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
}
```

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

**File:** rosetta/app/services/construction_service.go (L30-33)
```go
const (
	maxValidDurationSeconds         = 180
	defaultValidDurationSeconds     = maxValidDurationSeconds
	maxValidDurationNanos           = maxValidDurationSeconds * 1_000_000_000
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

**File:** rosetta/app/services/construction_service.go (L636-636)
```go
	sdkClient.SetMaxAttempts(1)
```
