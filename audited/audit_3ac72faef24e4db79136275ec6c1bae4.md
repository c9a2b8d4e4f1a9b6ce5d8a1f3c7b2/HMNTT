### Title
Raw SDK Error Leaks Internal Node Address via `ConstructionSubmit` Error Detail

### Summary
`ConstructionSubmit()` passes the raw, unsanitized error string from `hiero.TransactionExecute()` directly into the HTTP response body under the `"reason"` key of `ErrTransactionSubmissionFailed`. Because the Hiero SDK includes the target node's resolved network address (IP:port) in gRPC transport errors, any unauthenticated caller who submits a signed transaction targeting an unreachable node receives the internal address of that node in the API response. No privileges are required.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, `ConstructionSubmit()`, lines 355–362:

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    return nil, errors.AddErrorDetails(
        errors.ErrTransactionSubmissionFailed,
        "reason",
        fmt.Sprintf("%s", err),   // ← raw SDK error, verbatim
    )
}
```

`rosetta/app/errors/errors.go`, `AddErrorDetails()`, lines 106–112:

```go
func AddErrorDetails(err *types.Error, key, description string) *types.Error {
    clone := *err
    clone.Details = make(map[string]any)
    maps.Copy(clone.Details, err.Details)
    clone.Details[key] = description   // ← no sanitization
    return &clone
}
```

**Root cause:** `fmt.Sprintf("%s", err)` serialises the full Go error chain returned by the Hiero SDK's gRPC transport layer. When a node is unreachable, the gRPC stack produces errors of the form:

```
rpc error: code = Unavailable desc = failed to connect to all addresses;
last error: UNKNOWN: ipv4:10.0.1.7:50211: Failed to connect to remote host: connection refused
```

This string, including the internal `IP:port`, is placed verbatim into `Details["reason"]` and returned to the caller over HTTP.

**Failed assumption:** The code assumes the SDK error is opaque or safe to surface. It is not — gRPC errors embed the resolved transport address of the target node.

**Why existing checks are insufficient:**

- `ConstructionSubmit` validates only that the transaction deserialises correctly and is a supported type (`AccountCreateTransaction` or `TransferTransaction`). It performs **no validation** that the node account ID embedded in the submitted transaction belongs to the configured network.
- `sdkClient.SetMaxAttempts(1)` (line 636) disables SDK-level retry, so the first transport failure immediately surfaces the raw error.
- There is no allow-list check on the node account ID at submit time; the attacker fully controls which node the SDK attempts to contact.

### Impact Explanation
For deployments using `config.Rosetta.Nodes` (custom/private networks), the internal IP addresses and ports of consensus nodes are exposed to any unauthenticated caller. An attacker can enumerate all node addresses by iterating over known node account IDs, distinguish reachable from unreachable nodes, and map the internal network topology — all without any account or signing key beyond what is needed to construct a syntactically valid transaction. This constitutes a medium-severity information-disclosure vulnerability; it does not directly allow fund theft but materially aids targeted denial-of-service or lateral-movement planning against the node infrastructure.

### Likelihood Explanation
The `/construction/submit` endpoint is public by design in the Rosetta specification. Constructing a valid signed transaction requires only a key pair (which the attacker generates themselves) and knowledge of the Rosetta construction flow (public documentation). The attacker does not need an existing funded account — an `AccountCreateTransaction` with a self-generated key is sufficient. The attack is fully repeatable and scriptable, requiring no special network position.

### Recommendation
Replace the verbatim error string with a sanitized, opaque message before returning it to the caller:

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    return nil, errors.ErrTransactionSubmissionFailed  // no Details, or a fixed generic string
}
```

If a `"reason"` detail is required for operator diagnostics, strip transport-layer address information (e.g., via a regex or by inspecting the gRPC status code only) before including it in the response. Alternatively, log the full error server-side and return only the gRPC status code string (e.g., `"UNAVAILABLE"`) to the caller.

### Proof of Concept
1. Generate an Ed25519 key pair locally (no account needed).
2. Call `POST /construction/preprocess` with a `CRYPTO_TRANSFER` operation using the generated key as payer.
3. Call `POST /construction/metadata` — note the returned `node_account_id` (e.g., `0.0.3`).
4. Call `POST /construction/payloads` but **replace** `node_account_id` in the metadata with the account ID of a node known or suspected to be partitioned (e.g., `0.0.4`).
5. Sign the returned payload bytes with the generated private key.
6. Call `POST /construction/combine` with the signature.
7. Call `POST /construction/submit` with the resulting signed transaction hex.
8. Observe the HTTP 500 response body:
   ```json
   {
     "code": 118,
     "message": "Transaction submission failed",
     "retriable": false,
     "details": {
       "reason": "rpc error: code = Unavailable desc = ... ipv4:10.0.1.7:50211: connection refused"
     }
   }
   ```
   The internal address `10.0.1.7:50211` of the targeted node is disclosed.