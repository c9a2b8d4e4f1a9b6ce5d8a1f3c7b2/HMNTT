### Title
Hardcoded Ed25519 Private Key as Default `operatorKey` Enables Operator Impersonation and Transaction Interference

### Summary
In `pinger/config.go`, `loadConfig()` hardcodes a real Ed25519 private key (`302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137`) as the default value for the `operator-key` flag. Any unprivileged attacker who reads the public source code obtains this key verbatim and can sign and submit arbitrary Hiero network transactions — including smart contract calls — as the operator account (`0.0.2`), without any credentials or access to the running deployment.

### Finding Description
**Exact location:** `pinger/config.go`, `loadConfig()`, line 40:
```go
flag.StringVar(&cfg.operatorKey, "operator-key",
    envOr("HIERO_MIRROR_PINGER_OPERATOR_KEY",
        "302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137"),
    "operator private key string")
```

**Root cause:** The `envOr` helper (lines 140–145) returns the hardcoded literal whenever `HIERO_MIRROR_PINGER_OPERATOR_KEY` is absent from the environment. The validation block (lines 102–107) only rejects an *empty* key — it never checks whether the key equals the well-known default. `newClient()` in `sdk_client.go` (line 40) calls `hiero.PrivateKeyFromString(cfg.operatorKey)` and `client.SetOperator(opID, opKey)` (line 45), making the hardcoded key the live signing credential.

**Exploit flow:**
1. Attacker reads the public repository and extracts the DER-encoded private key from line 40.
2. Attacker decodes the key with any Hiero/Hedera SDK: `hiero.PrivateKeyFromString("302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137")`.
3. If the pinger is deployed without setting `HIERO_MIRROR_PINGER_OPERATOR_KEY`, the attacker now holds the identical signing key as the running pinger.
4. Attacker constructs and submits transactions signed by that key — transfers, contract calls, account updates — to the same network nodes the pinger targets.

**Why existing checks fail:** The only guard is `if cfg.operatorKey == ""` (line 105), which the hardcoded non-empty string trivially passes. There is no sentinel check, no warning log, and no runtime detection that the default key is in use.

### Impact Explanation
An attacker possessing the operator private key can:
- Submit `ContractExecuteTransaction` calls signed as the operator, altering smart contract state in ways the pinger's monitoring logic does not expect (e.g., draining contract-held HBAR, triggering unintended state transitions).
- Race the pinger's periodic `CryptoTransfer` (see `transfer.go` lines 29–31) by submitting conflicting transactions that exhaust the operator account's balance, causing the pinger to fail silently and produce false liveness/readiness signals (`/tmp/alive`, `/tmp/ready`).
- On any network where account `0.0.2` holds real value (previewnet genesis, custom "other" network), directly drain funds.

### Likelihood Explanation
Precondition is zero: the repository is public and the key is on line 40 in plaintext. Any operator who deploys the pinger without explicitly setting `HIERO_MIRROR_PINGER_OPERATOR_KEY` — a common misconfiguration in CI/CD or quick-start deployments — is immediately vulnerable. The attacker needs no network access to the deployment, no authentication, and no special tooling beyond a standard Hiero SDK.

### Recommendation
1. **Remove the hardcoded default entirely.** Change the default to `""` and make the validation block reject an empty key with a clear error, forcing operators to supply a real key explicitly.
2. **Add a sentinel check** that refuses to start if the supplied key matches the known-bad default literal.
3. **Document** that `HIERO_MIRROR_PINGER_OPERATOR_KEY` is mandatory in all deployment guides.

```go
// Recommended change in loadConfig():
flag.StringVar(&cfg.operatorKey, "operator-key",
    envOr("HIERO_MIRROR_PINGER_OPERATOR_KEY", ""),
    "operator private key string (required)")

// In validation:
const knownInsecureDefault = "302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137"
if cfg.operatorKey == "" {
    return cfg, fmt.Errorf("missing operator key (set -operator-key or HIERO_MIRROR_PINGER_OPERATOR_KEY)")
}
if cfg.operatorKey == knownInsecureDefault {
    return cfg, fmt.Errorf("operator key must not be the insecure hardcoded default")
}
```

### Proof of Concept
```bash
# Step 1: Extract key from public source (no privileges needed)
OPERATOR_KEY="302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137"
OPERATOR_ID="0.0.2"

# Step 2: Write a Go program using the Hiero SDK
cat > exploit.go << 'EOF'
package main

import (
    hiero "github.com/hiero-ledger/hiero-sdk-go/v2/sdk"
    "fmt"
)

func main() {
    key, _ := hiero.PrivateKeyFromString("302e020100300506032b65700422042091132178e72057a1d7528025956fe39b0b847f200ab59b2fdd367017f3087137")
    client, _ := hiero.ClientForName("testnet")
    opID, _ := hiero.AccountIDFromString("0.0.2")
    client.SetOperator(opID, key)

    // Submit a ContractExecuteTransaction or any other tx as the operator
    // This will succeed if the pinger was deployed with the default key
    fmt.Printf("Operator public key: %s\n", key.PublicKey().String())
    // ... submit competing transactions here
}
EOF

# Step 3: Run against testnet — succeeds if pinger uses default key
go run exploit.go
```