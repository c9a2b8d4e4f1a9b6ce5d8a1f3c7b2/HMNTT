### Title
Unauthenticated Log Flooding via Expired-Transaction Submission in `ConstructionSubmit`

### Summary
The `/construction/submit` endpoint accepts any structurally valid signed transaction from any unauthenticated caller and forwards it directly to the Hiero network. When the network rejects the transaction (e.g., due to an expired `validStart`), `log.Errorf` is called unconditionally with the full error string. Because no rate limiting or authentication exists anywhere in the middleware stack, an attacker can flood operator logs at will with zero cost.

### Finding Description
**Exact location:** `rosetta/app/services/construction_service.go`, `ConstructionSubmit()`, lines 332–368, specifically line 357.

```
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    ...
}
``` [1](#0-0) 

**Root cause:** `ConstructionSubmit` performs only three local checks before calling `TransactionExecute`:
1. Hex decode of the submitted bytes.
2. Protobuf unmarshal via `hiero.TransactionFromBytes`.
3. Type assertion — only `AccountCreateTransaction` or `TransferTransaction` are accepted. [2](#0-1) [3](#0-2) 

None of these checks inspect the `validStart` timestamp embedded in the transaction body. A transaction whose `validStart` is set to any time outside the Hiero node's acceptance window (typically ±3 minutes from current time) will pass all local checks, be forwarded to the network, be rejected with `TRANSACTION_EXPIRED`, and cause `log.Errorf` to fire.

**Failed assumption:** The code assumes that a structurally valid, correctly-typed transaction will succeed at the network level. It makes no attempt to validate semantic fields (timestamp, fee, signatures) before submission.

**Middleware stack — no rate limiting or authentication:**
The full middleware chain is `MetricsMiddleware → TracingMiddleware → CorsMiddleware → router`. None of these layers implement rate limiting or require authentication. [4](#0-3) 

The SDK is configured with `SetMaxAttempts(1)`, so each bad submission produces exactly one network round-trip and exactly one `log.Errorf` call — no amplification, but also no suppression. [5](#0-4) 

### Impact Explanation
An attacker can continuously emit `ERROR`-level log lines containing the full Hiero SDK error string. This degrades operator visibility by burying legitimate errors in noise, can exhaust log storage or log-shipping quotas, and may trigger false-positive alerting. There is no economic damage to network users, consistent with the Medium/griefing severity classification.

### Likelihood Explanation
The attack requires no credentials, no on-chain funds, and no special knowledge beyond the Rosetta API specification (which is public). A single script that constructs a minimal `TransferTransaction` protobuf with `validStart = 0`, hex-encodes it, and POSTs it to `/construction/submit` in a loop is sufficient. The endpoint is reachable by any network-adjacent party. The attack is trivially repeatable and automatable.

### Recommendation
1. **Validate `validStart` locally before submission.** Before calling `TransactionExecute`, extract the transaction ID's `validStart` from the deserialized transaction and reject it with a 4xx error (no `log.Errorf`) if it is already expired or unreasonably far in the future.
2. **Downgrade or gate the log level.** Use `log.Warnf` or `log.Debugf` for network-level rejections that originate from user-supplied data, reserving `log.Errorf` for internal/unexpected failures.
3. **Add rate limiting.** Introduce a per-IP or global rate-limiting middleware on the `/construction/submit` endpoint to bound the maximum log emission rate.

### Proof of Concept
```python
import requests, struct

# Minimal TransferTransaction protobuf with validStart = epoch 0
# (field 1 = TransactionBody with transactionID.transactionValidStart = {seconds:0, nanos:0})
# In practice, use the Hiero SDK to build a real TransferTransaction with:
#   validStart = time.Unix(0, 0)   # guaranteed expired
#   nodeAccountID = 0.0.3
#   any payer account

# 1. Build a valid AccountCreateTransaction or TransferTransaction with expired validStart
#    using the Hiero SDK (Go or Java), freeze it, sign it with any key.
# 2. Hex-encode the resulting bytes.
# 3. Loop:

import time, subprocess
while True:
    payload = {
        "network_identifier": {"blockchain": "Hiero", "network": "testnet"},
        "signed_transaction": "<hex-encoded expired tx>"
    }
    r = requests.post("http://<rosetta-host>:5700/construction/submit", json=payload)
    # Server logs: ERROR Failed to execute transaction ... TRANSACTION_EXPIRED
    time.sleep(0.05)  # 20 req/s, each producing one ERROR log line
```

Each iteration passes `unmarshallTransactionFromHexString` (valid protobuf, supported type), reaches `hiero.TransactionExecute`, is rejected by the node with `TRANSACTION_EXPIRED`, and triggers `log.Errorf` at line 357. [1](#0-0)

### Citations

**File:** rosetta/app/services/construction_service.go (L340-343)
```go
	transaction, rErr := unmarshallTransactionFromHexString(request.SignedTransaction)
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L355-362)
```go
	_, err = hiero.TransactionExecute(transaction, c.sdkClient)
	if err != nil {
		log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
		return nil, errors.AddErrorDetails(
			errors.ErrTransactionSubmissionFailed,
			"reason",
			fmt.Sprintf("%s", err),
		)
```

**File:** rosetta/app/services/construction_service.go (L636-636)
```go
	sdkClient.SetMaxAttempts(1)
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

**File:** rosetta/main.go (L217-219)
```go
	metricsMiddleware := middleware.MetricsMiddleware(router)
	tracingMiddleware := middleware.TracingMiddleware(metricsMiddleware)
	corsMiddleware := server.CorsMiddleware(tracingMiddleware)
```
