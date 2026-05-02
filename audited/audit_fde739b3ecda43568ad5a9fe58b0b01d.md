### Title
`ConstructionParse` Returns Spoofed `AccountIdentifierSigners` Without Cryptographic Signature Verification

### Summary
`ConstructionParse()` in `construction_service.go` populates `AccountIdentifierSigners` from the transaction body's negative-amount transfer accounts when `request.Signed = true`, without ever verifying that cryptographic signatures from those accounts are actually present in the transaction. Any unauthenticated caller can submit a crafted unsigned `TransferTransaction` with arbitrary account IDs in the debit side and receive a response falsely asserting those accounts signed the transaction, violating the Rosetta spec guarantee and misleading any downstream consumer that relies on this endpoint as a signing verification step.

### Finding Description

**Exact code path:**

`ConstructionParse()` — `rosetta/app/services/construction_service.go`, lines 183–215:
```go
operations, accounts, err := c.transactionHandler.Parse(ctx, transaction)  // line 198
...
if request.Signed {
    for _, account := range accounts {
        signers = append(signers, account.ToRosetta())  // lines 204-207
    }
}
```
`accounts` is returned by `Parse()` in `crypto_transfer_transaction_constructor.go`, lines 80–87:
```go
senderMap := senderMap{}
for _, operation := range operations {
    if operation.Amount.GetValue() < 0 {          // line 82
        senderMap[operation.AccountId.String()] = operation.AccountId  // line 83
    }
}
return operations, senderMap.toSenders(), nil     // line 87
```

**Root cause:** `Parse()` derives "signers" purely from the transaction body — accounts with negative HBAR amounts — with no inspection of the `sigMap` (signature map) embedded in the serialized `SignedTransaction` protobuf. `ConstructionParse()` then blindly promotes these body-derived accounts into `AccountIdentifierSigners` when `request.Signed = true`. The only place `ed25519.Verify` is called in the entire rosetta services layer is in `ConstructionCombine()` (line 82 of `construction_service.go`), which is a separate endpoint never invoked by `ConstructionParse()`.

**Failed assumption:** The implementation assumes that the presence of a negative-amount transfer for an account is equivalent to that account having cryptographically signed the transaction. This is false: the transaction body is attacker-controlled data with no integrity guarantee at the parse layer.

### Impact Explanation

The Rosetta spec mandates that when `signed=true`, `AccountIdentifierSigners` must reflect accounts whose signatures are **cryptographically present** in the transaction. This endpoint violates that contract. Any Rosetta client, middleware, or aggregator that calls `/construction/parse` with `signed=true` as a pre-submission verification step (the intended use per the Rosetta flow) will receive a falsely authoritative list of signers. A system that gates an action on "did account X sign this transaction?" by trusting this response can be deceived into believing account X approved a transaction it never touched. Additionally, an unsigned transaction submitted with `signed=true` passes through without error, giving no indication to the caller that signatures are absent.

### Likelihood Explanation

Exploitation requires zero privileges — the endpoint is unauthenticated and publicly reachable. The attacker only needs to construct a valid `TransferTransaction` protobuf (trivially done with the Hiero SDK or by hand-crafting the protobuf bytes) with the target account on the debit side, hex-encode it, and POST it to `/construction/parse` with `"signed": true`. This is repeatable, deterministic, and requires no special knowledge beyond the public API schema.

### Recommendation

When `request.Signed = true`, `ConstructionParse()` must verify that the transaction's embedded `sigMap` contains at least one valid Ed25519 signature over the `bodyBytes` for each account returned as a signer, mirroring the logic already present in `ConstructionCombine()`. Concretely:

1. After deserializing the transaction, extract `signedTransaction.SigMap` via `getFrozenTransactionBodyBytes` / `prototext.Unmarshal` (the infrastructure already exists at lines 648–656).
2. For each account in `senderMap`, verify that a valid signature from a key associated with that account exists in the `sigMap` before including it in `AccountIdentifierSigners`.
3. If `request.Signed = true` and no valid signatures are found, return an error rather than a response with an empty or fabricated signer list.

### Proof of Concept

1. Using the Hiero Go SDK, construct an unsigned `TransferTransaction` sending -100 tinybar from `0.0.1234` to `0.0.5678`, set a valid `TransactionID`, freeze it, and serialize to bytes:
   ```go
   tx := hiero.NewTransferTransaction().
       AddHbarTransfer(accountId1234, hiero.HbarFromTinybar(-100)).
       AddHbarTransfer(accountId5678, hiero.HbarFromTinybar(100)).
       SetTransactionID(hiero.TransactionIDGenerate(accountId1234))
   // Do NOT sign — no .Sign() call
   bytes, _ := hiero.TransactionToBytes(tx)
   hexTx := hex.EncodeToString(bytes)
   ```
2. POST to `/construction/parse`:
   ```json
   {
     "network_identifier": { "blockchain": "Hedera", "network": "testnet" },
     "signed": true,
     "transaction": "<hexTx>"
   }
   ```
3. Observe the response:
   ```json
   {
     "account_identifier_signers": [{ "address": "0.0.1234" }],
     ...
   }
   ```
   Account `0.0.1234` is reported as a signer despite no signature from that account being present in the transaction. The server returns HTTP 200 with no error. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rosetta/app/services/construction_service.go (L82-82)
```go
		if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
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
