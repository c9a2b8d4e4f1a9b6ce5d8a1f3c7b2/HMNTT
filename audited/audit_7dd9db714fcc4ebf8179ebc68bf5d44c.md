### Title
Internal Node Address and SDK Error Disclosure via Unsanitized Error Details in `ConstructionSubmit`

### Summary
In `ConstructionSubmit()`, when `hiero.TransactionExecute` fails (e.g., during a network partition or node unreachability), the raw SDK error string is passed verbatim into the Rosetta API response via `errors.AddErrorDetails`. The Hiero SDK's gRPC layer embeds the target node's address (IP:port) in connection failure errors, which are then serialized into the JSON response `details.reason` field and returned to any unauthenticated external caller. No sanitization or filtering of the error string occurs before it reaches the wire.

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
        fmt.Sprintf("%s", err),   // ← raw SDK error, unfiltered
    )
}
```

`rosetta/app/errors/errors.go`, `AddErrorDetails()`, lines 106–112:
```go
func AddErrorDetails(err *types.Error, key, description string) *types.Error {
    clone := *err
    clone.Details = make(map[string]any)
    maps.Copy(clone.Details, err.Details)
    clone.Details[key] = description   // ← placed directly into response body
    return &clone
}
```

**Root cause:** The failed assumption is that `err.Error()` from the Hiero SDK is safe to expose externally. In reality, the SDK's gRPC transport layer constructs error strings that include the dialed node endpoint. A typical failure during a network partition produces strings such as:

```
dial tcp 10.0.1.23:50211: connect: connection refused
```
or
```
rpc error: code = Unavailable desc = connection refused (node 35.237.200.180:50211)
```

These strings are returned verbatim in the JSON response body under `details.reason`. The Rosetta API has no authentication requirement; `/construction/submit` is callable by any external user.

**Why existing checks are insufficient:** The only guard is `c.IsOnline()` (line 336), which merely confirms the service is in online mode — it does nothing to sanitize error content. The `log.Errorf` call on line 357 correctly keeps the detail server-side, but the subsequent `AddErrorDetails` call on lines 358–362 duplicates the same raw string into the client-facing response.

### Impact Explanation
An attacker receives the internal node IP addresses and ports used by the Rosetta service's SDK client. For deployments using custom/private nodes (`config.Rosetta.Nodes`), this directly exposes private network topology (RFC-1918 addresses, internal hostnames, non-standard ports). Even for public-network deployments, the disclosure reveals which specific node was targeted, gRPC status codes, and SDK internals that aid further reconnaissance or targeted DoS against individual nodes. The Rosetta `types.Error.Details` map is part of the standard JSON response body, so no special tooling is needed to read it.

### Likelihood Explanation
The preconditions are minimal: the attacker needs only to submit a syntactically valid signed transaction (constructable via the public Rosetta construction flow with no credentials) and observe the error when any node is unreachable. Network partitions, node restarts, and firewall changes are routine operational events. The attacker can also repeatedly probe by submitting transactions and observing which errors contain address strings, making this repeatable and low-effort. No privilege escalation or insider access is required.

### Recommendation
Replace the raw SDK error with a generic, opaque message in the API response. The detailed error is already logged server-side (line 357) and does not need to be echoed to the caller:

```go
_, err = hiero.TransactionExecute(transaction, c.sdkClient)
if err != nil {
    log.Errorf("Failed to execute transaction %s (hash %s): %s", transactionId, hash, err)
    // Do NOT include raw err in the client response
    return nil, errors.ErrTransactionSubmissionFailed
}
```

If a caller-visible reason is required for debugging, sanitize the error to include only the gRPC status code (not the address), or map known SDK error types to fixed strings before passing to `AddErrorDetails`.

### Proof of Concept
1. Complete the Rosetta construction flow (`/preprocess` → `/metadata` → `/payloads` → `/combine`) to obtain a valid signed transaction hex.
2. Induce a network partition between the Rosetta service and the Hiero node (e.g., firewall rule blocking port 50211 to the node IP returned in `/metadata` as `node_account_id`).
3. POST the signed transaction to `/construction/submit`:
   ```json
   { "network_identifier": {...}, "signed_transaction": "0x..." }
   ```
4. Observe the JSON error response:
   ```json
   {
     "code": 118,
     "message": "Transaction submission failed",
     "retriable": false,
     "details": {
       "reason": "dial tcp 10.0.1.23:50211: connect: connection refused"
     }
   }
   ```
   The `details.reason` field contains the internal node address, confirming the disclosure.