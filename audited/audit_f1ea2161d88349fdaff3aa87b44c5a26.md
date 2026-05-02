### Title
Empty Transaction Hash Bypasses Validation and Triggers Unnecessary DB Query in `BlockTransaction()`

### Summary
When a user submits a `BlockTransactionRequest` with `TransactionIdentifier.Hash` set to `"0x"`, `SafeRemoveHexPrefix` strips the prefix and produces an empty string `""`. Go's `hex.DecodeString("")` returns `([]byte{}, nil)` — no error — so the intended `ErrInvalidTransactionIdentifier` guard is silently bypassed and a live DB query is issued with an empty `bytea` hash parameter. Any unauthenticated caller can repeat this indefinitely to force spurious DB round-trips.

### Finding Description
**Exact code path:**

- `rosetta/app/services/block_service.go`, `BlockTransaction()`, lines 87–92: `request.TransactionIdentifier.Hash` is forwarded verbatim to `FindByHashInBlock()` — no pre-validation, no `SafeRemoveHexPrefix` call on the transaction hash (only the block hash gets that treatment at line 81).
- `rosetta/app/persistence/transaction.go`, `FindByHashInBlock()`, line 180:
  ```go
  transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
  ```
- `rosetta/app/tools/hex.go`, `SafeRemoveHexPrefix()`, lines 18–22: input `"0x"` → returns `""`.
- Go stdlib: `hex.DecodeString("")` → `([]byte{}, nil)`. **No error is returned.**
- Lines 181–183: the `err != nil` guard is never entered; `ErrInvalidTransactionIdentifier` is never returned.
- Lines 188–193: the ORM executes `selectTransactionsByHashInTimestampRange` with `sql.Named("hash", []byte{})`, i.e. `WHERE … AND transaction_hash = ''::bytea`.
- Line 198–200: zero rows returned → `ErrTransactionNotFound`.

**Root cause / failed assumption:** The developer assumed that a bare `"0x"` prefix (no actual hash bytes) would be rejected by `hex.DecodeString`, but the Go standard library treats an empty string as valid hex, returning an empty byte slice without error.

**Why existing checks fail:** The only guard is `if err != nil` after `hex.DecodeString`. Because `hex.DecodeString("")` succeeds, the check is structurally incapable of catching the `"0x"` input. There is no length/minimum-bytes check on `transactionHash` before the query is issued.

### Impact Explanation
The concrete effect is that every `"0x"` transaction hash request causes a real database query to execute against the `transaction` table (bounded by the block's timestamp range, but still a live round-trip). The intended fast-fail path (`ErrInvalidTransactionIdentifier`) is skipped. An attacker can flood the `/block/transaction` endpoint with such requests to amplify DB load without any authentication or rate-limiting at the application layer. There is no data exfiltration, no state mutation, and no economic damage; the severity is griefing / availability degradation.

### Likelihood Explanation
The `/block/transaction` endpoint is unauthenticated and publicly reachable in any standard Rosetta deployment. The payload is trivial to construct (a valid block identifier plus `"0x"` as the transaction hash). The attack is fully repeatable and requires no special knowledge or privilege. Any automated scanner or malicious client can discover and exploit this in seconds.

### Recommendation
Add an explicit minimum-length check on `transactionHash` immediately after decoding, before the DB query:

```go
transactionHash, err := hex.DecodeString(tools.SafeRemoveHexPrefix(hashStr))
if err != nil || len(transactionHash) == 0 {
    return nil, hErrors.ErrInvalidTransactionIdentifier
}
```

This ensures that a bare `"0x"` (or an empty string) is rejected at the application layer before any DB interaction occurs, restoring the intended fast-fail behaviour.

### Proof of Concept
1. Identify any valid block (index + hash) in the network, e.g. block index `1`, hash `"0xABCD…"`.
2. Send a POST to `/block/transaction`:
   ```json
   {
     "network_identifier": { ... },
     "block_identifier": { "index": 1, "hash": "0xABCD..." },
     "transaction_identifier": { "hash": "0x" }
   }
   ```
3. Observe that the server does **not** return `ErrInvalidTransactionIdentifier`; instead it returns `ErrTransactionNotFound`, confirming the DB query was executed.
4. Repeat in a tight loop to generate sustained DB load with no authentication required.