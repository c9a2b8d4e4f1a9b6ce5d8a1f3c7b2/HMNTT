### Title
Unbounded Slice Index on `GetNodeAccountIDs()[0]` in `ConstructionSubmit` Causes Runtime Panic (DoS)

### Summary
In `ConstructionSubmit()`, the call `transaction.GetNodeAccountIDs()[0]` at line 353 is made unconditionally without verifying the slice is non-empty. The upstream deserialization function `unmarshallTransactionFromHexString()` validates only hex decoding, protobuf parseability, and transaction type — it never asserts that node account IDs are present. An unauthenticated attacker can submit a crafted, protobuf-valid `TransferTransaction` or `AccountCreateTransaction` with no `nodeAccountID` field set, causing a Go runtime panic (index out of range) in the logging statement before any network execution occurs.

### Finding Description
**Exact code path:**

- `rosetta/app/services/construction_service.go`, `ConstructionSubmit()`, lines 340–353
- `unmarshallTransactionFromHexString()`, lines 658–674

**Root cause:**

`unmarshallTransactionFromHexString` performs three checks:
1. Hex decode succeeds (line 659–661)
2. `hiero.TransactionFromBytes` succeeds (line 664–667)
3. Transaction type is `AccountCreateTransaction` or `TransferTransaction` (lines 669–671)

There is **no check** that the deserialized transaction has at least one node account ID. After returning, `ConstructionSubmit` immediately indexes into the result of `GetNodeAccountIDs()` at line 353:

```go
log.Infof("Submitting transaction %s (hash %s) to node %s", transactionId,
    hash, transaction.GetNodeAccountIDs()[0])   // line 353 — no len() guard
```

In the Hiero Go SDK, `TransactionFromBytes` parses a raw `SignedTransaction` protobuf. The `nodeAccountID` field inside `TransactionBody` is optional in protobuf3 — if absent, the SDK leaves the node account IDs slice empty. A crafted protobuf that omits this field will parse successfully, pass the type check, and reach line 353 with an empty slice, triggering `index out of range`.

**Why existing checks are insufficient:**

`isSupportedTransactionType` only inspects the Go type of the deserialized transaction object; it says nothing about the presence or count of node account IDs. `TransactionGetTransactionHash` (lines 345–348) operates on the raw serialized bytes and succeeds independently of whether node account IDs are set.

### Impact Explanation
A Go runtime panic that is not recovered crashes the serving goroutine. The coinbase `rosetta-sdk-go` framework's router does not guarantee panic recovery at the handler level; the middleware present in this codebase (`health.go`, `metrics.go`, `trace.go`) provides no panic recovery. Repeated requests with this crafted payload can continuously crash handler goroutines, rendering the `/construction/submit` endpoint (and potentially the entire Rosetta process) unavailable. No authentication or privileged access is required — the endpoint is publicly reachable in online mode.

### Likelihood Explanation
The exploit requires only the ability to POST to `/construction/submit` with a hex-encoded protobuf payload. Constructing a minimal valid `TransferTransaction` protobuf without a `nodeAccountID` field is trivial using any protobuf library. The attack is repeatable, stateless, and requires no prior knowledge of the network state. Any unprivileged external user can trigger it.

### Recommendation
Add an explicit length guard before indexing:

```go
nodeIDs := transaction.GetNodeAccountIDs()
if len(nodeIDs) == 0 {
    return nil, errors.ErrInternalServerError // or a dedicated ErrMissingNodeAccountId
}
log.Infof("Submitting transaction %s (hash %s) to node %s", transactionId, hash, nodeIDs[0])
```

Alternatively, add a validation step inside `unmarshallTransactionFromHexString` (or a new `validateTransaction` helper) that rejects any deserialized transaction whose `GetNodeAccountIDs()` slice is empty, returning a well-typed Rosetta error to the caller before any further processing.

### Proof of Concept
1. Using any protobuf library, construct a minimal `SignedTransaction` protobuf where `bodyBytes` encodes a `TransactionBody` of type `CryptoTransfer` (maps to `TransferTransaction`) with **no** `nodeAccountID` field set.
2. Serialize to bytes, hex-encode with `0x` prefix.
3. POST to the online Rosetta `/construction/submit` endpoint:
   ```json
   {
     "network_identifier": { "blockchain": "Hedera", "network": "testnet" },
     "signed_transaction": "0x<crafted_hex>"
   }
   ```
4. The server reaches line 353, calls `GetNodeAccountIDs()[0]` on an empty slice, and panics with `runtime error: index out of range [0] with length 0`.
5. Repeat to sustain denial of service.