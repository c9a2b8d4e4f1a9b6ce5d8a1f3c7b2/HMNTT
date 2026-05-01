### Title
Unbounded Goroutine Accumulation via Context-Discarding `ConstructionSubmit` with No SDK Request Timeout

### Summary
`ConstructionSubmit` in `rosetta/app/services/construction_service.go` discards the incoming HTTP request context and calls `hiero.TransactionExecute(transaction, c.sdkClient)` with no deadline. No `SetRequestTimeout` is configured on the SDK client. The HTTP server's `WriteTimeout` (default 10 s) closes the TCP connection but does **not** cancel the goroutine, so each in-flight submit goroutine blocks for the SDK's full internal timeout (~2 min default) regardless of whether the client has already disconnected. An unprivileged attacker can flood the endpoint to accumulate thousands of blocked goroutines, exhausting process memory and starving the scheduler.

### Finding Description
**Exact location:**
- `rosetta/app/services/construction_service.go:332–368` — `ConstructionSubmit` signature uses `_ context.Context` (context discarded).
- Line 355: `_, err = hiero.TransactionExecute(transaction, c.sdkClient)` — no context, no per-call deadline.
- `rosetta/app/services/construction_service.go:636` — `sdkClient.SetMaxAttempts(1)` limits retries to one attempt but sets **no** `SetRequestTimeout`, leaving the SDK's default (~2 min) in effect.

**Root cause:** The HTTP request context, which carries the `WriteTimeout`-derived cancellation signal, is thrown away at the function signature. The SDK call therefore cannot be interrupted by the HTTP layer. When the SDK's gRPC transport stalls (e.g., TCP connection established to a slow/unresponsive consensus node, no response), the goroutine parks until the SDK's own internal deadline fires — up to ~2 minutes per request.

**Why existing checks fail:**
- `WriteTimeout: rosettaConfig.Http.WriteTimeout` (default 10 s, `rosetta/main.go:226`) closes the TCP connection to the *client* after 10 s, but Go's `net/http` does **not** cancel the handler goroutine; it only makes the `ResponseWriter` return errors on the next write.
- `sdkClient.SetMaxAttempts(1)` (`construction_service.go:636`) prevents SDK-level retries but does not bound the single-attempt wall-clock time.
- No rate-limiting or concurrency cap exists on the `/construction/submit` endpoint.

**Exploit flow:**
1. Attacker crafts valid signed transactions (no funds needed — the transaction can be syntactically valid but target a node that is slow or whose TCP port is reachable but unresponsive).
2. Attacker sends a high volume of POST `/construction/submit` requests concurrently.
3. Each request spawns a goroutine that blocks inside `hiero.TransactionExecute` for up to ~2 minutes.
4. Goroutines accumulate; each holds stack memory (initially ~2–8 KB, growing with call depth) plus gRPC stream state.
5. Process memory is exhausted or the Go scheduler is overwhelmed, causing OOM or severe latency for all other endpoints.

### Impact Explanation
Every goroutine blocked in `TransactionExecute` holds live memory and a gRPC connection slot. At 1,000 concurrent stalled requests, the process carries ~1,000 goroutines each blocked for up to 120 s. This is sufficient to exhaust memory on a typical container (256–512 MB limit) or saturate the gRPC connection pool, preventing legitimate transactions from being gossiped. The Rosetta `/construction/submit` endpoint is the sole path for broadcasting transactions; its unavailability halts all transaction submission through the mirror node's Rosetta interface.

### Likelihood Explanation
The endpoint is unauthenticated and publicly reachable. The attacker needs only the ability to send HTTP POST requests and construct a syntactically valid signed transaction (no private key for a funded account is required — the transaction can be crafted to fail at the node level, but the SDK still waits for a response). Targeting a specific node account ID in the transaction body (via the `node_account_id` metadata field set during `/construction/payloads`) allows the attacker to direct all submissions to a single slow node, maximising hang duration. This is repeatable and scriptable with standard HTTP tooling.

### Recommendation
1. **Propagate the request context:** Change the signature from `_ context.Context` to `ctx context.Context` and pass it (with an added deadline) to the SDK call.
2. **Set an SDK request timeout:** Call `sdkClient.SetRequestTimeout(duration)` in `NewConstructionAPIService` with a value shorter than `WriteTimeout` (e.g., 8 s when `WriteTimeout` is 10 s).
3. **Add a per-call deadline:** Wrap the execute call:
   ```go
   callCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
   defer cancel()
   _, err = hiero.TransactionExecuteWithContext(callCtx, transaction, c.sdkClient)
   ```
4. **Add concurrency limiting:** Use a semaphore or `golang.org/x/sync/semaphore` to cap simultaneous in-flight `TransactionExecute` calls.

### Proof of Concept
```bash
# 1. Obtain a valid signed transaction hex (any syntactically valid tx targeting a slow node).
# 2. Send 500 concurrent requests:
for i in $(seq 1 500); do
  curl -s -X POST http://<rosetta-host>:5700/construction/submit \
    -H 'Content-Type: application/json' \
    -d '{"network_identifier":{"blockchain":"Hiero","network":"mainnet"},
         "signed_transaction":"<valid_hex_tx>"}' &
done
wait
# 3. Observe: process RSS grows continuously; subsequent legitimate submit
#    requests time out or receive 5xx errors as the scheduler is saturated.
```

Each background `curl` returns after `WriteTimeout` (10 s) with a write error, but the server-side goroutine remains blocked inside `hiero.TransactionExecute` for up to ~2 minutes, confirmed by the absence of any context cancellation path from line 333 (`_ context.Context`) through line 355 (`hiero.TransactionExecute`). [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/services/construction_service.go (L332-355)
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
```

**File:** rosetta/app/services/construction_service.go (L635-636)
```go
	// disable SDK auto retry
	sdkClient.SetMaxAttempts(1)
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
