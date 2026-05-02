Looking at the full `ConstructionParse` implementation and the `Parse()` methods of the transaction constructors to understand exactly how `AccountIdentifierSigners` is populated.

### Title
`ConstructionParse` Returns Unverified `AccountIdentifierSigners` Without Validating Embedded Signatures

### Summary
`ConstructionParse` with `request.Signed = true` populates `AccountIdentifierSigners` from the transaction body's structural fields (sender accounts / payer account ID) without verifying that the cryptographic signatures embedded in the transaction actually correspond to those accounts. Any unauthenticated caller can craft a transaction body naming arbitrary victim accounts as senders, attach attacker-controlled signatures, and receive a response that falsely asserts those victim accounts authorized the transaction.

### Finding Description

**Exact code path:**

In `rosetta/app/services/construction_service.go`, `ConstructionParse` (lines 183–215):

```go
operations, accounts, err := c.transactionHandler.Parse(ctx, transaction)  // line 198
// ...
if request.Signed {
    for _, account := range accounts {
        signers = append(signers, account.ToRosetta())  // lines 204-207
    }
}
```

The `accounts` slice is populated by `transactionHandler.Parse()`. For `cryptoTransferTransactionConstructor.Parse()` (`rosetta/app/services/construction/crypto_transfer_transaction_constructor.go`, lines 80–87), signers are derived entirely from the transaction body's `HbarTransfers` map — specifically, any account with a negative transfer amount is returned as a signer:

```go
for _, operation := range operations {
    if operation.Amount.GetValue() < 0 {
        senderMap[operation.AccountId.String()] = operation.AccountId
    }
}
return operations, senderMap.toSenders(), nil
```

For `cryptoCreateTransactionConstructor.Parse()` (`rosetta/app/services/construction/crypto_create_transaction_constructor.go`, line 115), the signer is the payer from `GetTransactionID().AccountID`.

**Root cause:** Neither `ConstructionParse` nor the underlying `Parse()` implementations inspect the `sigMap` (signature map) embedded in the serialized transaction. The `AccountIdentifierSigners` field is populated purely from transaction body fields that the attacker fully controls.

**Why existing checks fail:** `ConstructionCombine` (lines 72–87 of `construction_service.go`) does perform `ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes)` before embedding signatures. However, `ConstructionParse` performs no equivalent check. An attacker bypasses `ConstructionCombine` entirely by constructing the signed transaction hex directly (e.g., using the Hiero SDK or raw protobuf), embedding their own valid-but-irrelevant signatures, and submitting it straight to `ConstructionParse`.

**Exploit flow:**
1. Attacker generates their own Ed25519 keypair (`attacker_priv`, `attacker_pub`).
2. Attacker constructs a `TransferTransaction` with: sender = `0.0.VICTIM` (−100 HBAR), receiver = `0.0.ATTACKER` (+100 HBAR), `TransactionID` payer = `0.0.VICTIM`.
3. Attacker freezes the transaction and signs it with `attacker_priv` (a valid signature over the body bytes, just not from the victim's key).
4. Attacker serializes to hex and POSTs to `/construction/parse` with `signed: true`.
5. Server deserializes, calls `Parse()`, finds `0.0.VICTIM` as the negative-amount sender, and returns `AccountIdentifierSigners: [{"address": "0.0.VICTIM"}]`.
6. Downstream system reads this response and concludes `0.0.VICTIM` has authorized the transfer.

### Impact Explanation
Any system that relies on `ConstructionParse`'s `AccountIdentifierSigners` to confirm multi-party authorization — such as an exchange's withdrawal pipeline, a multi-sig coordinator, or an automated compliance monitor — can be deceived into believing a victim account has approved a transaction it never signed. This enables fraudulent authorization attestation at the Rosetta API layer. The Rosetta spec explicitly states that when `signed=true`, `AccountIdentifierSigners` must reflect accounts that *have* signed; violating this contract breaks the trust model of the entire construction workflow.

### Likelihood Explanation
The attack requires zero privileges — the `/construction/parse` endpoint is a public, unauthenticated, offline endpoint by design. The attacker needs only the Hiero SDK (or raw protobuf tooling) to construct a valid serialized transaction, which is trivial. The attack is fully repeatable and requires no on-chain interaction. Any operator exposing the Rosetta API publicly is immediately vulnerable to this deception.

### Recommendation
In `ConstructionParse`, when `request.Signed == true`, extract the `sigMap` from the deserialized transaction's `SignedTransaction` protobuf and verify that each account listed in `AccountIdentifierSigners` has a corresponding valid Ed25519 signature over the `bodyBytes`. Concretely, reuse the same `getFrozenTransactionBodyBytes` + `ed25519.Verify` pattern already present in `ConstructionCombine` (lines 67–84 of `construction_service.go`). If any required signer lacks a valid signature, return an error rather than a response that implies authorization.

### Proof of Concept

```go
// 1. Generate attacker keypair
attackerPriv, _ := hiero.PrivateKeyGenerateEd25519()

// 2. Build transfer: victim sends, attacker receives
tx := hiero.NewTransferTransaction().
    AddHbarTransfer(victimAccountId, hiero.HbarFromTinybar(-100)).
    AddHbarTransfer(attackerAccountId, hiero.HbarFromTinybar(100)).
    SetTransactionID(hiero.TransactionIDGenerate(victimAccountId)).
    SetNodeAccountIDs([]hiero.AccountID{nodeAccountId})
tx.Freeze()

// 3. Sign with ATTACKER key (not victim's key)
tx.Sign(attackerPriv)
txBytes, _ := tx.ToBytes()
txHex := hex.EncodeToString(txBytes)

// 4. POST to /construction/parse
// { "network_identifier": {...}, "signed": true, "transaction": "<txHex>" }

// 5. Response contains:
// { "account_identifier_signers": [{"address": "0.0.VICTIM"}], ... }
// — falsely asserting victim authorized the transaction
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/services/construction_service.go (L72-84)
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
```

**File:** rosetta/app/services/construction_service.go (L183-215)
```go
func (c *constructionAPIService) ConstructionParse(
	ctx context.Context,
	request *rTypes.ConstructionParseRequest,
) (*rTypes.ConstructionParseResponse, *rTypes.Error) {
	transaction, err := unmarshallTransactionFromHexString(request.Transaction)
	if err != nil {
		return nil, err
	}

	metadata := make(map[string]any)
	memo, _ := hiero.TransactionGetTransactionMemo(transaction)
	if memo != "" {
		metadata[types.MetadataKeyMemo] = memo
	}

	operations, accounts, err := c.transactionHandler.Parse(ctx, transaction)
	if err != nil {
		return nil, err
	}

	signers := make([]*rTypes.AccountIdentifier, 0, len(accounts))
	if request.Signed {
		for _, account := range accounts {
			signers = append(signers, account.ToRosetta())
		}
	}

	return &rTypes.ConstructionParseResponse{
		AccountIdentifierSigners: signers,
		Metadata:                 metadata,
		Operations:               operations.ToRosetta(),
	}, nil
}
```

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L80-87)
```go
	senderMap := senderMap{}
	for _, operation := range operations {
		if operation.Amount.GetValue() < 0 {
			senderMap[operation.AccountId.String()] = operation.AccountId
		}
	}

	return operations, senderMap.toSenders(), nil
```
