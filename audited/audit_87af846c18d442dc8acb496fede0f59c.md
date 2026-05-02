### Title
Unbounded Request Body and No Rate Limiting on `/construction/hash` Enables CPU/Memory Exhaustion DoS

### Summary
The `ConstructionHash` endpoint in `rosetta/app/services/construction_service.go` performs `hex.DecodeString`, protobuf deserialization via `hiero.TransactionFromBytes`, and hash computation on attacker-controlled input with no request body size cap and no rate limiting. An unprivileged external attacker can flood the endpoint with many concurrent requests carrying arbitrarily large hex-encoded payloads, exhausting CPU and memory and rendering the Rosetta node unavailable.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, lines 117–134 (`ConstructionHash`) calls `unmarshallTransactionFromHexString(request.SignedTransaction)`, which performs `hex.DecodeString` (allocates `len(input)/2` bytes) and `hiero.TransactionFromBytes` (protobuf parse, CPU-proportional to payload size), followed by `hiero.TransactionGetTransactionHash`.

`rosetta/main.go`, lines 220–227 constructs the `http.Server` with only timeout fields (`ReadTimeout`, `WriteTimeout`, `ReadHeaderTimeout`, `IdleTimeout`) — no `http.MaxBytesReader` wrapper and no middleware enforcing a maximum body size or per-IP/global request rate.

**Root cause:** The server accepts and fully processes arbitrarily large `signed_transaction` strings. `ReadTimeout` limits *how long* the body can be read, but within that window a high-bandwidth attacker can deliver megabytes per request. With many concurrent goroutines, each allocating and parsing a large payload, CPU and heap pressure accumulate.

**Why existing checks are insufficient:**
- HTTP timeouts (`ReadTimeout` etc.) bound per-connection read time but do not cap body size; a fast connection can still deliver a large payload within the timeout.
- The Rosetta asserter validates network identifiers and operation types but imposes no size constraint on `signed_transaction`.
- No rate-limiting middleware is present anywhere in the rosetta handler chain (confirmed by grep across all `rosetta/**/*.go`).
- `hex.DecodeString` returns an error on invalid hex, but valid oversized hex strings pass through to the expensive deserialization step.

### Impact Explanation
A sustained flood of concurrent POST requests to `/construction/hash` with large (e.g., multi-MB) hex strings causes:
- Heap allocations proportional to `N_concurrent × payload_size` (hex decode output + protobuf parse buffers).
- CPU saturation from protobuf deserialization and hash computation.
- Legitimate Rosetta clients (wallets, exchanges) receive timeouts or connection refusals, breaking transaction submission workflows.

The endpoint is available in both online and offline modes, widening the attack surface.

### Likelihood Explanation
The endpoint is unauthenticated and publicly reachable by design (Rosetta spec). No special knowledge or credentials are required. A single attacker with a moderate network connection can open dozens of concurrent HTTP/1.1 connections and send large payloads. The attack is trivially repeatable and scriptable (e.g., with `curl`, `wrk`, or the existing k6 test harness at `tools/k6/src/rosetta/test/constructionHash.js`).

### Recommendation
1. **Enforce a maximum request body size** by wrapping the router with `http.MaxBytesReader` (e.g., 64 KB, matching the maximum valid Hiero transaction size) in `rosetta/main.go` before the handler chain.
2. **Add rate limiting middleware** (e.g., `golang.org/x/time/rate` token-bucket per source IP) applied to all construction endpoints.
3. **Validate `signed_transaction` length** early in `ConstructionHash` (and `ConstructionCombine`, `ConstructionParse`) before any decoding, returning `ErrTransactionDecodeFailed` immediately for oversized inputs.

### Proof of Concept
```bash
# Generate a large valid-hex string (~2 MB of zero bytes encoded as hex)
LARGE_HEX=$(python3 -c "print('00' * 1_000_000)")

# Flood with 50 concurrent requests
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/construction/hash \
    -H 'Content-Type: application/json' \
    -d "{\"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
         \"signed_transaction\":\"${LARGE_HEX}\"}" &
done
wait
# Observe: CPU spikes to 100%, legitimate requests time out
```

Each request causes `hex.DecodeString` to allocate ~1 MB, then `hiero.TransactionFromBytes` to attempt protobuf parse on that buffer. With 50 concurrent goroutines this is ~50 MB of live allocations plus proportional CPU, repeatable indefinitely. [1](#0-0) [2](#0-1)

### Citations

**File:** rosetta/app/services/construction_service.go (L117-134)
```go
func (c *constructionAPIService) ConstructionHash(
	_ context.Context,
	request *rTypes.ConstructionHashRequest,
) (*rTypes.TransactionIdentifierResponse, *rTypes.Error) {
	signedTransaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
	if rErr != nil {
		return nil, rErr
	}

	hash, err := hiero.TransactionGetTransactionHash(signedTransaction)
	if err != nil {
		return nil, errors.ErrTransactionHashFailed
	}

	return &rTypes.TransactionIdentifierResponse{
		TransactionIdentifier: &rTypes.TransactionIdentifier{Hash: tools.SafeAddHexPrefix(hex.EncodeToString(hash[:]))},
	}, nil
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
