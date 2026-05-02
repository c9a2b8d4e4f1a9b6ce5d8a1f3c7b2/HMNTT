### Title
Unguarded Slice Index Access in `getSdkPayerAccountId` Causes Exploitable Runtime Panic via Malformed `account_map` Metadata

### Summary
In `rosetta/app/services/construction_service.go`, the function `getSdkPayerAccountId` splits each comma-separated entry of the user-supplied `account_map` metadata on `:` and immediately accesses `mapping[1]` without checking the slice length. An unprivileged attacker can supply an `account_map` entry that passes the `strings.HasPrefix` guard but contains no `:` separator, causing a `runtime error: index out of range [1] with length 1` panic. Go's `net/http` server recovers per-connection panics so the process does not exit, but the request goroutine panics and the connection is closed without any Rosetta error response, making this a reliable per-request denial-of-service.

### Finding Description

**Exact location:** `rosetta/app/services/construction_service.go`, function `getSdkPayerAccountId`, lines 491–501.

```go
for aliasMap := range strings.SplitSeq(accountMap, ",") {
    if !strings.HasPrefix(aliasMap, payerAlias) {
        continue
    }
    var err error
    mapping := strings.Split(aliasMap, ":")   // line 497
    if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {  // line 498 – PANIC
        return zero, errors.ErrInvalidAccount
    }
    break
}
```

**Root cause:** `strings.Split(s, ":")` returns a slice of length 1 when `s` contains no `:`. The code unconditionally dereferences `mapping[1]` with no `len(mapping) >= 2` guard.

**Exploit flow:**

1. `payerAlias` is `payerAccountId.String()`. For alias accounts this is `"0x" + hex.EncodeToString(alias)` — a pure hex string that never contains `:`. [1](#0-0) 

2. `accountMapMetadata` is read directly from the attacker-controlled `request.Metadata[metadataKeyAccountMap]` with no format validation. [2](#0-1) 

3. The attacker sets `account_map` to the exact payer alias string with no colon (e.g., `"0x3a21<pubkey_hex>"`). `strings.HasPrefix` returns `true`, `strings.Split` returns a one-element slice, and `mapping[1]` panics. [3](#0-2) 

**Why existing checks fail:** The `strings.HasPrefix` guard (line 492) only confirms the entry starts with the alias; it does not require a `:` to be present. The `accountMapMetadata == nil` and type-assertion checks (lines 480–487) only validate that the field is a non-nil string — they say nothing about its internal format. [4](#0-3) 

### Impact Explanation
Every `POST /construction/payloads` request that uses an alias-based payer account can be made to panic. The Go `net/http` server's built-in per-connection recovery prevents a full process crash, but the panicking goroutine closes the connection without writing any HTTP response. The legitimate caller receives a connection-reset error instead of a structured Rosetta error. Repeated requests exhaust goroutine/connection resources and pollute logs with stack traces, constituting a reliable, unauthenticated denial-of-service against the construction workflow.

### Likelihood Explanation
The `/construction/payloads` endpoint is a standard, publicly documented Rosetta API endpoint requiring no authentication. The `metadata` field is a free-form `map[string]any` accepted verbatim from the JSON body. Any client that can reach the service can trigger the panic in a single HTTP request. The precondition — an alias-based payer — is trivially satisfied by supplying a valid hex-encoded public key as the operation account address, which the service itself accepts and promotes to an alias account. The attack is fully repeatable and requires no prior knowledge beyond the public Rosetta specification.

### Recommendation
Add a bounds check immediately after the split:

```go
mapping := strings.Split(aliasMap, ":")
if len(mapping) != 2 {
    return zero, errors.ErrInvalidAccount
}
if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {
    return zero, errors.ErrInvalidAccount
}
```

Alternatively, use `strings.Cut(aliasMap, ":")` which returns an explicit `found bool` and avoids slice indexing entirely:

```go
_, accountStr, found := strings.Cut(aliasMap, ":")
if !found {
    return zero, errors.ErrInvalidAccount
}
if payer, err = hiero.AccountIDFromString(accountStr); err != nil {
    return zero, errors.ErrInvalidAccount
}
```

### Proof of Concept

**Preconditions:** Rosetta service reachable; any valid network/operation type that produces an alias-based payer (e.g., `CRYPTO_TRANSFER` with a `0x<hex_pubkey>` account address).

**Steps:**

1. Obtain a valid Ed25519 or ECDSA public key and hex-encode it with the protobuf prefix, e.g.:
   `PAYER_ALIAS="0x1220<32-byte-ed25519-pubkey-hex>"`

2. Send a well-formed `ConstructionPayloads` request where:
   - `operations[0].account.address` = `PAYER_ALIAS`
   - `metadata.account_map` = `PAYER_ALIAS` *(no colon, no mapped account ID)*
   - All other required metadata fields (`node_account_id`, `valid_start_nanos`, etc.) are valid.

3. **Expected (buggy) result:** The server goroutine panics with `runtime error: index out of range [1] with length 1`; the TCP connection is reset; no HTTP response body is returned.

4. **Expected (fixed) result:** The server returns a structured `ErrInvalidAccount` Rosetta error with HTTP 500.

### Citations

**File:** rosetta/app/domain/types/account_id.go (L50-54)
```go
func (a AccountId) String() string {
	if a.HasAlias() {
		return tools.SafeAddHexPrefix(hex.EncodeToString(a.alias))
	}
	return a.accountId.String()
```

**File:** rosetta/app/services/construction_service.go (L243-246)
```go
	payer, rErr := c.getSdkPayerAccountId(signers[0], request.Metadata[metadataKeyAccountMap])
	if rErr != nil {
		return nil, rErr
	}
```

**File:** rosetta/app/services/construction_service.go (L480-487)
```go
	if accountMapMetadata == nil {
		return zero, errors.ErrAccountNotFound
	}

	accountMap, ok := accountMapMetadata.(string)
	if !ok {
		return zero, errors.ErrAccountNotFound
	}
```

**File:** rosetta/app/services/construction_service.go (L491-501)
```go
	for aliasMap := range strings.SplitSeq(accountMap, ",") {
		if !strings.HasPrefix(aliasMap, payerAlias) {
			continue
		}

		var err error
		mapping := strings.Split(aliasMap, ":")
		if payer, err = hiero.AccountIDFromString(mapping[1]); err != nil {
			return zero, errors.ErrInvalidAccount
		}
		break
```
