Based on my direct code inspection, I can confirm the key claims in this report.

**Verified facts:**

1. Line 352–353 of `rosetta/app/services/construction_service.go` unconditionally accesses `transaction.GetNodeAccountIDs()[0]` with no preceding length check. [1](#0-0) 

2. Between the `unmarshallTransactionFromHexString` call at line 340 and the `[0]` access at line 353, there is no guard on the length of `GetNodeAccountIDs()`. [2](#0-1) 

3. `hiero.TransactionGetTransactionHash` (line 345) and `hiero.TransactionGetTransactionID` (line 351) are both called before the panic site, and neither would enforce the presence of node account IDs. [3](#0-2) 

The root cause is confirmed in the source. The report is accurate.

---

# Audit Report

## Title
Index Out-of-Bounds Panic in `ConstructionSubmit` via Crafted Transaction with No Node Account IDs

## Summary
`ConstructionSubmit` in `rosetta/app/services/construction_service.go` unconditionally accesses `transaction.GetNodeAccountIDs()[0]` at line 353 without verifying the slice is non-empty. An unauthenticated attacker can submit a hex-encoded Hedera transaction that passes all existing validation but contains no node account IDs, triggering a runtime panic and crashing or disrupting the `/construction/submit` endpoint.

## Finding Description
In `rosetta/app/services/construction_service.go`, `ConstructionSubmit` (lines 332–368):

1. `unmarshallTransactionFromHexString` (line 340) decodes the hex, calls `hiero.TransactionFromBytes`, and validates only that the transaction type is `AccountCreateTransaction` or `TransferTransaction`. It does **not** check for the presence of node account IDs. [4](#0-3) 

2. `hiero.TransactionGetTransactionHash` (line 345) and `hiero.TransactionGetTransactionID` (line 351) are called and can both succeed on a transaction with an empty node account ID list. [3](#0-2) 

3. Line 353 then executes `transaction.GetNodeAccountIDs()[0]` with no length guard. If the deserialized transaction has an empty node account ID list — which is valid per protobuf encoding since the field is optional — this produces a runtime panic: `runtime error: index out of range [0] with length 0`. [1](#0-0) 

The failed assumption is that any transaction successfully deserialized from bytes will always have at least one node account ID. This holds for transactions produced by the normal Rosetta construction flow (which calls `transactionSetNodeAccountId`), but is not enforced for externally-submitted transactions.

## Impact Explanation
A panic in a Go HTTP handler goroutine that is not caught by a recovery middleware will crash the entire server process, taking down the Rosetta online endpoint. Even with panic recovery middleware, the request fails and the transaction is not gossiped. This is a denial-of-service vector against the `/construction/submit` endpoint — the only endpoint responsible for broadcasting transactions to the Hedera network. Repeated requests can keep the service unavailable.

## Likelihood Explanation
No authentication or privilege is required. The `/construction/submit` endpoint is publicly accessible per the Rosetta API specification. Crafting a valid `TransferTransaction` protobuf with no `nodeAccountID` field set is trivial using any Hedera/Hiero SDK or raw protobuf tooling. The attack is repeatable and requires minimal effort.

## Recommendation
Add an explicit length check before accessing `GetNodeAccountIDs()[0]`. For example:

```go
nodeIDs := transaction.GetNodeAccountIDs()
if len(nodeIDs) == 0 {
    return nil, errors.ErrInvalidTransaction // or a suitable error
}
log.Infof("Submitting transaction %s (hash %s) to node %s", transactionId, hash, nodeIDs[0])
```

Alternatively, enforce the presence of at least one node account ID inside `unmarshallTransactionFromHexString` so the validation is centralised and applies to all callers.

## Proof of Concept
1. Using any Hiero/Hedera SDK, construct a `TransferTransaction` with valid sender, recipient, and amount, but **do not call `SetNodeAccountIDs`** (leave the node account ID list empty).
2. Sign the transaction with a valid key pair.
3. Serialize to bytes and hex-encode.
4. POST to `/construction/submit` with the hex string as `signed_transaction`.
5. The server reaches line 353, calls `GetNodeAccountIDs()[0]` on an empty slice, and panics with `runtime error: index out of range [0] with length 0`.

### Citations

**File:** rosetta/app/services/construction_service.go (L340-353)
```go
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
```
