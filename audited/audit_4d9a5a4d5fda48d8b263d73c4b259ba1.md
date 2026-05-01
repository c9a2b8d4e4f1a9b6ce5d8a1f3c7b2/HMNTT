### Title
Unbounded Concurrent Request Flooding in `ConstructionSubmit` Exhausts Goroutines and Hiero Node Connections

### Summary
`ConstructionSubmit()` in `rosetta/app/services/construction_service.go` performs no application-level rate limiting, concurrency control, or authentication before calling `unmarshallTransactionFromHexString()` and `hiero.TransactionExecute()`. Any unauthenticated external caller can flood the endpoint with concurrent requests carrying syntactically valid but signature-less transaction hex strings, causing unbounded goroutine spawning and gRPC connection exhaustion toward Hiero consensus nodes, degrading or denying service to legitimate users.

### Finding Description
**Exact code path:**

`ConstructionSubmit()` (lines 332–368, `rosetta/app/services/construction_service.go`):
```
336: if !c.IsOnline() { ... }          // only check: online mode
340: transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
345: hashBytes, err := hiero.TransactionGetTransactionHash(transaction)
355: _, err = hiero.TransactionExecute(transaction, c.sdkClient)
```

`unmarshallTransactionFromHexString()` (lines 658–674):
```
659: transactionBytes, err := hex.DecodeString(...)   // CPU + memory: hex decode
664: transaction, err := hiero.TransactionFromBytes(transactionBytes)  // protobuf deserialization
669: if rErr := isSupportedTransactionType(transaction); rErr != nil { // type check AFTER deserialization
```

`isSupportedTransactionType()` (lines 676–685) only allows `AccountCreateTransaction` or `TransferTransaction`. An attacker can trivially craft a valid protobuf for either type with no valid signature.

**Root cause:** There is no application-level rate limiter, semaphore, or concurrency cap anywhere in the request path. The Go HTTP server (`rosetta/main.go` lines 220–227) sets only I/O timeouts (`ReadTimeout`, `WriteTimeout`) but no `MaxHeaderBytes`, no connection limit, and no goroutine cap. The middleware stack (`rosetta/main.go` lines 217–219) consists only of metrics, tracing, and CORS — zero throttling.

**Why existing checks fail:**

The Traefik middleware in `charts/hedera-mirror-rosetta/values.yaml` (lines 149–166) defines `inFlightReq: amount: 5` per source IP and `rateLimit: average: 10` per `requestHost`. These are insufficient because:
1. `global.middleware: false` (line 95) — the global middleware flag is disabled by default, meaning the middleware may not be applied in all deployments.
2. The `rateLimit` is keyed on `requestHost` (the server's hostname), not per client IP — it is effectively a global cap shared across all users, not a per-attacker limit.
3. Traefik ingress is bypassed entirely when the attacker reaches the pod directly (e.g., via `NodePort`, `LoadBalancer`, or internal cluster access).
4. A distributed attack from multiple IPs bypasses the per-IP `inFlightReq` limit.
5. The `retry: attempts: 3` middleware actually amplifies load by retrying failed requests up to 3 times.

`sdkClient.SetMaxAttempts(1)` (line 636) disables SDK-level retries, but each request still makes one blocking gRPC call to a Hiero node, holding a goroutine and a connection for the full round-trip duration.

### Impact Explanation
Each concurrent request to `/construction/submit` with a valid-but-unsigned `TransferTransaction` or `AccountCreateTransaction` protobuf will:
1. Spawn a goroutine (Go HTTP server model — one goroutine per request, unbounded).
2. Deserialize the protobuf (CPU + heap allocation proportional to payload size).
3. Open a gRPC connection to a Hiero consensus node and block until the node responds with a rejection (invalid signature).

Under sustained flood (e.g., 1,000 concurrent connections), the server accumulates thousands of goroutines each blocked on `hiero.TransactionExecute()`. This exhausts the gRPC connection pool to Hiero nodes, causes memory pressure from goroutine stacks (~8 KB each, growing under I/O wait), and delays or drops legitimate `/construction/submit` requests. The Hiero nodes themselves may also throttle or ban the mirror node's IP due to the volume of invalid submissions, further degrading service. No HBAR fees are incurred by the attacker because the Hiero node rejects unsigned transactions before charging.

### Likelihood Explanation
The attack requires zero privileges, zero credentials, and zero economic cost. The attacker only needs:
- Network access to the Rosetta API port (5700 by default).
- A single valid protobuf skeleton for `TransferTransaction` (publicly documented, trivially constructable from the Hiero protobuf schema).

The attack is fully repeatable and automatable with standard HTTP load tools (e.g., `wrk`, `hey`, `ab`). Deployments that expose the Rosetta API publicly (as intended for Coinbase Rosetta compatibility) are directly reachable. The Traefik middleware mitigation is not guaranteed to be active (`global.middleware: false`) and is bypassable.

### Recommendation
1. **Application-level concurrency cap**: Add a semaphore or `golang.org/x/sync/semaphore` guard in `ConstructionSubmit()` to limit simultaneous in-flight executions (e.g., 20–50).
2. **Per-IP rate limiting in the application**: Integrate a token-bucket rate limiter (e.g., `golang.org/x/time/rate` with a per-IP map) directly in the HTTP middleware stack in `rosetta/main.go`, applied before routing.
3. **Request body size limit**: Set `http.Server.MaxHeaderBytes` and wrap the router with `http.MaxBytesReader` to reject oversized payloads before deserialization.
4. **Enforce Traefik middleware unconditionally**: Change `global.middleware: false` to `true` in `charts/hedera-mirror-rosetta/values.yaml` and switch `rateLimit.sourceCriterion` from `requestHost` to `ipStrategy` for per-client enforcement.
5. **Pre-deserialization size check**: In `unmarshallTransactionFromHexString()`, reject hex strings exceeding the maximum valid Hiero transaction size (~6 KB) before calling `hiero.TransactionFromBytes()`.

### Proof of Concept
**Preconditions:** Rosetta API reachable at `http://<host>:5700`. Traefik middleware not enforced (default `global.middleware: false`).

**Step 1 — Craft a minimal valid `TransferTransaction` protobuf (no valid signature required):**
```python
# Using hiero-sdk or raw protobuf; a minimal TransferTransaction body is ~50 bytes
# Hex-encode it
signed_tx_hex = "0x" + minimal_transfer_tx_bytes.hex()
```

**Step 2 — Flood `/construction/submit` with concurrent requests:**
```bash
# Using wrk or hey
hey -n 100000 -c 1000 -m POST \
  -H "Content-Type: application/json" \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"signed_transaction":"<signed_tx_hex>"}' \
  http://<host>:5700/construction/submit
```

**Step 3 — Observe:**
- Server goroutine count spikes (visible via `/metrics` → `go_goroutines`).
- `hiero_mirror_rosetta_request_inflight` gauge climbs without bound.
- Legitimate `/construction/submit` requests time out or receive 5xx errors.
- Hiero node connection pool saturates; `TransactionExecute` calls begin queuing or failing.
- Server logs fill with: `Failed to execute transaction ... : INVALID_SIGNATURE` at high rate. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** rosetta/app/services/construction_service.go (L634-636)
```go

	// disable SDK auto retry
	sdkClient.SetMaxAttempts(1)
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

**File:** rosetta/app/services/construction_service.go (L676-685)
```go
func isSupportedTransactionType(transaction hiero.TransactionInterface) *rTypes.Error {
	switch transaction.(type) {
	case hiero.AccountCreateTransaction:
	case hiero.TransferTransaction:
	default:
		return errors.ErrTransactionInvalidType
	}

	return nil
}
```

**File:** rosetta/main.go (L217-227)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L88-96)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
  namespaceOverride: ""
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
