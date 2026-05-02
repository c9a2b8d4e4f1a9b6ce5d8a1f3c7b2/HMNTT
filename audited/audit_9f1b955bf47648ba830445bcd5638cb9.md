### Title
Unbounded Hash Length in `BlockTransaction()` Enables Memory/CPU Exhaustion DoS

### Summary
`BlockTransaction()` in `rosetta/app/services/block_service.go` passes `request.TransactionIdentifier.Hash` directly to `FindByHashInBlock()` without any length validation. Inside `FindByHashInBlock()`, `hex.DecodeString` is called on the raw attacker-controlled string, allocating memory proportional to the input length. The HTTP server has no body-size limit (`http.MaxBytesReader` is never set), so an unauthenticated attacker can send arbitrarily large valid hex strings to exhaust memory and CPU across concurrent requests.

### Finding Description
**Exact code path:**

`rosetta/app/services/block_service.go`, lines 87–92 (`BlockTransaction`):
```go
transaction, err := s.FindByHashInBlock(
    ctx,
    request.TransactionIdentifier.Hash,   // ← raw, unvalidated attacker string
    block.ConsensusStartNanos,
    block.ConsensusEndNanos,
)
```

`rosetta/app/persistence/transaction.go`, line 180 (`FindByHashInBlock`):
```go
transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
```

`hex.DecodeString` allocates `len(input)/2` bytes for any valid hex string. There is no length check before this call. The only guard is that non-hex characters cause an early return of `ErrInvalidTransactionIdentifier` — a valid hex string of any length passes through.

**HTTP server (rosetta/main.go, lines 220–227):**
```go
httpServer := &http.Server{
    Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
    Handler:           corsMiddleware,
    IdleTimeout:       rosettaConfig.Http.IdleTimeout,
    ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
    ReadTimeout:       rosettaConfig.Http.ReadTimeout,   // default 5s
    WriteTimeout:      rosettaConfig.Http.WriteTimeout,
}
```
`http.MaxBytesReader` is never applied. The `ReadTimeout` (default 5 s) limits transfer time but not payload size — a high-bandwidth attacker can still deliver tens of megabytes per request. JSON deserialization allocates the string once; `hex.DecodeString` allocates a second buffer of half that size. With concurrent requests, heap pressure multiplies linearly.

**Why existing checks fail:**
- The Rosetta SDK `asserter` validates network identifiers and operation types, not hash string length.
- `hex.DecodeString` validates only hex character set, not length.
- No middleware enforces a maximum request body size.
- `ReadTimeout` bounds time, not bytes.

### Impact Explanation
An unauthenticated attacker can send concurrent POST `/block/transaction` requests each carrying a multi-megabyte valid hex string in `transaction_identifier.hash`. Each request causes two large heap allocations (JSON string + decoded byte slice). Sustained flooding exhausts available memory, triggering OOM kills or severe GC pressure, rendering the Rosetta node unavailable. This directly disrupts exchange integrations that depend on the Rosetta API for block/transaction data, which can affect asset custody and settlement operations on the network.

### Likelihood Explanation
The `/block/transaction` endpoint is publicly reachable (Kubernetes ingress exposes `/rosetta/block` with no authentication layer in the default chart configuration). No credentials, tokens, or privileged access are required. The attack requires only the ability to send HTTP POST requests. It is trivially scriptable and repeatable with standard tools (`curl`, `wrk`, etc.). The attacker only needs to know the endpoint path and supply a syntactically valid (but arbitrarily long) hex string.

### Recommendation
1. **Enforce a maximum request body size** at the HTTP server level by wrapping the handler with `http.MaxBytesReader` (e.g., 64 KB is more than sufficient for any legitimate Rosetta request).
2. **Validate hash length before decoding** in `FindByHashInBlock()`: a Hedera transaction hash is at most 48 bytes (96 hex chars) or 32 bytes (64 hex chars). Reject any input exceeding 98 characters (96 hex + optional `0x` prefix) with `ErrInvalidTransactionIdentifier` before calling `hex.DecodeString`.
3. Optionally add the same guard in `BlockTransaction()` itself before delegating to `FindByHashInBlock()`.

### Proof of Concept
```bash
# Generate a 10 MB valid hex string
BIGHASH=$(python3 -c "print('ab' * 5_000_000)")

# Send concurrent requests to the /block/transaction endpoint
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>:5700/block/transaction \
    -H 'Content-Type: application/json' \
    -d "{
      \"network_identifier\": {\"blockchain\": \"Hedera\", \"network\": \"mainnet\"},
      \"block_identifier\": {\"index\": 1, \"hash\": \"0x0000000000000000000000000000000000000000000000000000000000000001\"},
      \"transaction_identifier\": {\"hash\": \"$BIGHASH\"}
    }" &
done
wait
# Observe: server memory spikes by ~(10 MB JSON string + 5 MB decoded bytes) × 50 = ~750 MB
# Repeated waves cause OOM or severe GC stalls, making the node unresponsive
```