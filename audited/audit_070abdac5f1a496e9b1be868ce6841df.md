### Title
Unsanitized Node Error Message Leakage via `ConstructionSubmit` / `AddErrorDetails`

### Summary
In `ConstructionSubmit()`, when `hiero.TransactionExecute()` fails, the raw Hiero SDK error string is passed verbatim through `fmt.Sprintf("%s", err)` into `AddErrorDetails()`, which embeds it in the Rosetta API response returned to the caller. Any unprivileged user who submits a transaction that the node rejects receives the full internal SDK error string, which can include account state codes (`INSUFFICIENT_PAYER_BALANCE`, `PAYER_ACCOUNT_DELETED`, `ACCOUNT_FROZEN_FOR_TOKEN`, etc.) and potentially gRPC-level connection details including node IP addresses and ports.

### Finding Description

**Exact code path:**

`rosetta/app/services/construction_service.go`, lines 355–363: [1](#0-0) 

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    return nil, errors.AddErrorDetails(
        errors.ErrTransactionSubmissionFailed,
        "reason",
        fmt.Sprintf("%s", err),   // <-- raw SDK error, no sanitization
    )
}
```

`rosetta/app/errors/errors.go`, lines 106–112: [2](#0-1) 

`AddErrorDetails()` clones the error and stores the raw string under the `"reason"` key in `Details`, which is serialized into the JSON response body.

**Root cause:** There is no sanitization or extraction of only the structured status code from the SDK error. `fmt.Sprintf("%s", err)` converts the entire error chain to a string. The Hiero Go SDK error for a rejected transaction includes the full precheck/consensus status string (e.g., `exceptional precheck status INSUFFICIENT_PAYER_BALANCE received by node 0.0.3`) and, for transport-level failures, the full gRPC error including node IP and port (e.g., `rpc error: code = Unavailable desc = connection refused to 34.94.106.61:50211`).

**Failed assumption:** The code assumes the SDK error string is safe to return to external callers. It is not — it is an opaque internal error that may contain sensitive operational details.

**No existing sanitization:** There is no allowlist, no extraction of only the `Status` field, and no stripping of network addresses before the string is embedded in the response.

### Impact Explanation

1. **Account state probing**: An attacker submits transactions targeting arbitrary payer accounts and reads back status codes like `INSUFFICIENT_PAYER_BALANCE`, `PAYER_ACCOUNT_DELETED`, `ACCOUNT_FROZEN_FOR_TOKEN`, `ACCOUNT_EXPIRED_AND_PENDING_REMOVAL`, `PAYER_ACCOUNT_NOT_FOUND`. This allows systematic enumeration of account states without any on-chain query permission.

2. **Network topology disclosure**: gRPC transport errors include the IP address and port of the specific consensus node the mirror node's SDK client attempted to contact. This reveals internal node addresses that may not be publicly documented, aiding targeted DoS or man-in-the-middle positioning.

3. **Transaction replay/duplicate detection**: `DUPLICATE_TRANSACTION` confirms a transaction ID was already submitted and is within the 180-second receipt window, enabling timing attacks.

4. **Aiding transaction tampering**: Knowing an account's balance status (`INSUFFICIENT_PAYER_BALANCE`) or frozen state (`ACCOUNT_FROZEN_FOR_TOKEN`) allows an attacker to craft transactions that are more likely to succeed, or to selectively target accounts in degraded states.

### Likelihood Explanation

The `/construction/submit` endpoint is publicly accessible to any Rosetta API client with no authentication requirement. The attacker needs only to construct a syntactically valid signed transaction (which the Rosetta construction flow itself guides them through) and submit it with a payer account they wish to probe. The error is deterministic and repeatable — the same account state query can be repeated at will. No special privileges, keys, or network access beyond the public Rosetta API are required.

### Recommendation

Replace the raw `fmt.Sprintf("%s", err)` with a sanitized extraction that returns only the structured Hiero status code:

```go
// Extract only the status code string, not the full SDK error chain
reason := "UNKNOWN"
if statusErr, ok := err.(interface{ Status() string }); ok {
    reason = statusErr.Status()
} else {
    // fallback: return a generic message, not the raw error
    reason = "transaction rejected by node"
}
return nil, errors.AddErrorDetails(
    errors.ErrTransactionSubmissionFailed,
    "reason",
    reason,
)
```

Alternatively, map the SDK error to a fixed set of allowed status strings using a switch/allowlist, and return a generic `"transaction rejected"` for any unrecognized error type. The full error detail should remain only in the server-side log (line 357), which already exists.

### Proof of Concept

1. Obtain access to a running Hiero Mirror Node Rosetta API (online mode).
2. Use the Rosetta construction flow (`/preprocess` → `/metadata` → `/payloads` → `/combine`) to build a valid signed `CryptoTransfer` transaction with payer account `0.0.X` where `X` is an account you wish to probe.
3. Set the transfer amount to exceed the account's balance.
4. POST the signed transaction to `/construction/submit`.
5. Observe the JSON response body:
```json
{
  "code": 118,
  "message": "Transaction submission failed",
  "retriable": false,
  "details": {
    "reason": "exceptional precheck status INSUFFICIENT_PAYER_BALANCE received by node 0.0.3"
  }
}
```
6. Repeat with different account IDs and observe `PAYER_ACCOUNT_NOT_FOUND`, `PAYER_ACCOUNT_DELETED`, `ACCOUNT_FROZEN_FOR_TOKEN`, etc. to map account states.
7. For network topology: submit a transaction when the configured node is unreachable and observe the gRPC error containing the node's IP address and port in the `"reason"` field.

### Citations

**File:** rosetta/app/services/construction_service.go (L355-363)
```go
	_, err = hiero.TransactionExecute(transaction, c.sdkClient)
	if err != nil {
		log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
		return nil, errors.AddErrorDetails(
			errors.ErrTransactionSubmissionFailed,
			"reason",
			fmt.Sprintf("%s", err),
		)
	}
```

**File:** rosetta/app/errors/errors.go (L106-112)
```go
func AddErrorDetails(err *types.Error, key, description string) *types.Error {
	clone := *err
	clone.Details = make(map[string]any)
	maps.Copy(clone.Details, err.Details)
	clone.Details[key] = description
	return &clone
}
```
