### Title
Information Disclosure of Internal Node Addresses via Raw SDK Error in `ConstructionSubmit`

### Summary
In `ConstructionSubmit()`, when `hiero.TransactionExecute` fails (e.g., during a network partition), the raw Go SDK error is converted to a string via `fmt.Sprintf("%s", err)` and embedded verbatim into the Rosetta API error response under `details.reason`. Because Go's gRPC transport errors include the target endpoint address (e.g., `dial tcp 35.237.200.180:50211: connect: connection refused`), any unauthenticated caller can read internal node IP addresses and ports directly from the HTTP response body.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, `ConstructionSubmit()`, lines 355–363:
```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    return nil, errors.AddErrorDetails(
        errors.ErrTransactionSubmissionFailed,
        "reason",
        fmt.Sprintf("%s", err),   // raw SDK error → HTTP response
    )
}
```

`rosetta/app/errors/errors.go`, `AddErrorDetails()`, lines 106–112:
```go
func AddErrorDetails(err *types.Error, key, description string) *types.Error {
    clone := *err
    clone.Details = make(map[string]any)
    maps.Copy(clone.Details, err.Details)
    clone.Details[key] = description   // raw string placed in response map
    return &clone
}
```

**Root cause:** The failed assumption is that the Hiero SDK error is safe to surface externally. In Go, gRPC transport failures embed the dialed endpoint in the error string (e.g., `rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp <NODE_IP>:<PORT>: connect: connection refused"`). `AddErrorDetails` places this string into `Details["reason"]`, which the Rosetta SDK serializes as-is into the JSON HTTP response body. There is zero sanitization between the SDK error and the wire response.

**Compounding factor:** `sdkClient.SetMaxAttempts(1)` (line 636) disables SDK-level retries, so the first gRPC failure is immediately propagated to the caller with no buffering or wrapping.

### Impact Explanation
An attacker learns the IP addresses and gRPC ports of every consensus node the mirror node is configured to use. This constitutes network topology disclosure: the attacker can map the private node infrastructure, target specific nodes for DoS, or use the addresses to probe for additional vulnerabilities on those hosts. The Rosetta `/construction/submit` endpoint is a public, unauthenticated API by design, so no privilege is required to trigger this.

### Likelihood Explanation
Exploitation requires only: (1) the ability to POST a syntactically valid signed transaction (trivially constructable using the public Rosetta flow), and (2) a condition where at least one node is unreachable — which can be induced by the attacker themselves (e.g., flooding the node's gRPC port to cause connection refusal) or occurs naturally during maintenance windows or real partitions. The attack is repeatable, requires no credentials, and produces a deterministic, machine-readable result in the JSON response.

### Recommendation
Replace the raw error string with a generic, sanitized message before embedding it in the response. The internal error should continue to be logged server-side (as it already is via `log.Errorf`), but the client-facing detail must not contain transport-layer information:

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    return nil, errors.ErrTransactionSubmissionFailed  // no Details, or sanitized detail only
}
```

If a client-visible reason is required, map SDK error categories (e.g., gRPC status codes) to generic strings (`"network_unavailable"`, `"node_timeout"`) without including any address or transport detail.

### Proof of Concept
1. Use the Rosetta construction flow (`/preprocess` → `/metadata` → `/payloads` → `/combine`) to produce a valid signed transaction hex.
2. Ensure or wait for a condition where the configured consensus node is unreachable (or induce it by blocking the node's gRPC port from the mirror node host).
3. POST to `/construction/submit`:
   ```json
   { "network_identifier": {...}, "signed_transaction": "0x<hex>" }
   ```
4. Observe the HTTP 500 response body:
   ```json
   {
     "code": 118,
     "message": "Transaction submission failed",
     "retriable": false,
     "details": {
       "reason": "rpc error: code = Unavailable desc = connection error: desc = \"transport: Error while dialing: dial tcp 35.237.200.180:50211: connect: connection refused\""
     }
   }
   ```
5. The value of `details.reason` discloses the internal node IP (`35.237.200.180`) and gRPC port (`50211`).