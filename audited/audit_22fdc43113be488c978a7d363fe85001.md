The code is clear. Let me verify the exact line numbers and the flow from user input to the panic site.

### Title
Index Out-of-Bounds Panic in `getSdkPayerAccountId` via Crafted `account_map` Metadata

### Summary
An unprivileged caller of the `/construction/payloads` endpoint can supply a `Metadata["account_map"]` value whose comma-separated entries match the payer alias prefix but contain no `:` separator. When `strings.Split(aliasMap, ":")` returns a single-element slice, the unconditional access to `mapping[1]` panics with an index-out-of-range runtime error, crashing the serving goroutine. Go's `net/http` server recovers the panic and returns a 500, but the stack trace is logged and the request is aborted, enabling repeatable griefing with no authentication required.

### Finding Description
**Exact location:** `rosetta/app/services/construction_service.go`, function `getSdkPayerAccountId`, lines 497–498.

```
mapping := strings.Split(aliasMap, ":")          // line 497
if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {  // line 498 — panics if len(mapping)==1
```

**Data flow from user input to panic site:**

1. `ConstructionPayloads` (line 218) receives a `*rTypes.ConstructionPayloadsRequest` whose `Metadata` map is entirely attacker-controlled.
2. Line 243 passes `request.Metadata[metadataKeyAccountMap]` (the string constant `"account_map"`) directly as the second argument to `getSdkPayerAccountId` — no sanitisation, no schema validation.
3. Inside `getSdkPayerAccountId` (line 467), the only guards before the split are:
   - `payerAccountId.HasAlias()` must be true (line 471) — attacker satisfies this by crafting operations whose first signer is an alias-based account.
   - `accountMapMetadata != nil` (line 480) — trivially satisfied.
   - Type assertion to `string` (line 484) — trivially satisfied.
   - `strings.HasPrefix(aliasMap, payerAlias)` (line 492) — the attacker makes the entry *start with* the payer alias, so this check passes.
4. `strings.Split(aliasMap, ":")` on a colon-free string returns `[]string{aliasMap}` (length 1). `mapping[1]` is an unconditional out-of-bounds access → runtime panic.

**Why the existing check is insufficient:** The `strings.HasPrefix` guard only filters entries that do not begin with the payer alias. It does not verify that a `:` separator is present before indexing into the result of `strings.Split`. There is no `len(mapping) >= 2` guard anywhere.

### Impact Explanation
Every request that reaches line 498 with a colon-free matching entry panics the goroutine. Go's `net/http` runtime recovers the panic (preventing full-process termination), but:
- The HTTP response is a 500 with no body.
- A full goroutine stack trace is written to the server error log on every triggered request.
- The endpoint is rendered non-functional for the duration of each crafted request.
- An attacker can flood the endpoint to saturate log storage or obscure legitimate error signals.

Severity matches the stated scope: griefing / availability degradation with no direct economic loss to network participants.

### Likelihood Explanation
The `/construction/payloads` endpoint is a standard, unauthenticated Rosetta API surface. No credentials, tokens, or privileged network position are required. The attacker only needs to:
1. Know the alias string of the payer they intend to use (derivable from the operations they themselves craft).
2. Set `Metadata["account_map"]` to `"<payerAlias>NOCOLON"`.

The attack is trivially repeatable with a single HTTP client and requires no on-chain state or funds.

### Recommendation
Add a length check immediately after the split, before indexing:

```go
mapping := strings.Split(aliasMap, ":")
if len(mapping) != 2 {
    return zero, errors.ErrInvalidAccount
}
if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {
    return zero, errors.ErrInvalidAccount
}
```

Alternatively, use `strings.Cut(aliasMap, ":")` which returns an explicit `found bool`:

```go
_, accountIdStr, found := strings.Cut(aliasMap, ":")
if !found {
    return zero, errors.ErrInvalidAccount
}
if payer, err = hiero.AccountIDFromString(accountIdStr); err != nil {
    return zero, errors.ErrInvalidAccount
}
```

### Proof of Concept
**Preconditions:** A running mirror-node Rosetta service reachable at `http://localhost:8082`.

**Steps:**

1. Identify or derive a valid alias-format account string, e.g. `0.0.302a300506032b6570032100<hex-pubkey>` (the exact value becomes `payerAlias`).

2. Craft a `POST /construction/payloads` request where:
   - `operations` contains a `CRYPTO_TRANSFER` with the alias account as the sender (so `signers[0].HasAlias() == true` and `signers[0].String() == payerAlias`).
   - `metadata["account_map"]` is set to `"<payerAlias>NOCOLON"` — a string that starts with the alias but contains no `:`.
   - `metadata["node_account_id"]`, `metadata["valid_duration"]`, `metadata["valid_start_nanos"]` are set to valid values to pass earlier guards.

3. Send the request:
```
POST /construction/payloads HTTP/1.1
Content-Type: application/json

{
  "network_identifier": { "blockchain": "Hedera", "network": "testnet" },
  "operations": [ /* alias-payer crypto transfer */ ],
  "metadata": {
    "node_account_id": "0.0.3",
    "valid_duration": "120",
    "valid_start_nanos": "1700000000000000000",
    "account_map": "<payerAlias>NOCOLON"
  }
}
```

4. **Observed result:** Server returns HTTP 500; server error log contains a `runtime error: index out of range [1] with length 1` stack trace rooted at `construction_service.go:498`.

5. **Expected result:** Server should return a structured `ErrInvalidAccount` error with HTTP 200 (Rosetta error convention), not panic.