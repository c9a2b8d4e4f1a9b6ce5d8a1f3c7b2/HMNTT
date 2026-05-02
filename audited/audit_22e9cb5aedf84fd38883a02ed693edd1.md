### Title
`ConstructionParse` Returns Victim Account as `AccountIdentifierSigner` Without Signature Verification

### Summary
`ConstructionParse()` accepts an arbitrary transaction hex and, when `request.Signed = true`, returns accounts extracted from the transaction body as `AccountIdentifierSigners` with no cryptographic verification that those accounts actually signed the transaction. An unprivileged attacker can craft a transaction encoding any victim account as the payer (`TransactionID.AccountID`), submit it to the endpoint, and receive a Rosetta response falsely asserting the victim is a confirmed signer.

### Finding Description

**Code path:**

In `rosetta/app/services/construction_service.go`, `ConstructionParse()` (lines 183–215):

```go
transaction, err := unmarshallTransactionFromHexString(request.Transaction)
// ...
operations, accounts, err := c.transactionHandler.Parse(ctx, transaction)
// ...
signers := make([]*rTypes.AccountIdentifier, 0, len(accounts))
if request.Signed {
    for _, account := range accounts {
        signers = append(signers, account.ToRosetta())
    }
}
return &rTypes.ConstructionParseResponse{
    AccountIdentifierSigners: signers, ...
}, nil
``` [1](#0-0) 

The `accounts` slice is populated by `c.transactionHandler.Parse()`. For `AccountCreateTransaction`, `cryptoCreateTransactionConstructor.Parse()` (lines 63–116 of `crypto_create_transaction_constructor.go`) extracts the payer directly from the transaction body field `TransactionID.AccountID`:

```go
payer, err := types.NewAccountIdFromSdkAccountId(*cryptoCreateTransaction.GetTransactionID().AccountID)
// ...
return types.OperationSlice{operation}, []types.AccountId{payer}, nil
``` [2](#0-1) 

**Root cause:** `ConstructionParse()` performs zero signature verification before populating `AccountIdentifierSigners`. The `TransactionID.AccountID` field is a plain protobuf field in the transaction body — any caller can set it to any account ID. The only check performed is that the transaction deserializes correctly and is of a supported type (`isSupportedTransactionType`). [3](#0-2) 

**Why existing checks are insufficient:** `ConstructionCombine()` does perform `ed25519.Verify` on each signature against the frozen body bytes (line 82), but `ConstructionParse()` has no equivalent check. The `unmarshallTransactionFromHexString` helper only validates the transaction type, not signatures. [4](#0-3) 

### Impact Explanation
Any downstream system or Rosetta client that calls `/construction/parse` with `signed=true` and trusts `account_identifier_signers` as proof of consent will be deceived. An attacker can produce a Rosetta API response that falsely asserts a victim account authorized a transaction. This violates the Rosetta specification's guarantee that `account_identifier_signers` represents accounts that have cryptographically signed the transaction, and can be used to bypass authorization checks in systems built on top of this API.

### Likelihood Explanation
The attack requires no privileges, no credentials, and no knowledge beyond the victim's public account ID (which is public on Hedera). The attacker only needs to serialize a valid `AccountCreateTransaction` or `TransferTransaction` protobuf with the victim's account ID in the `TransactionID` field and POST it to the publicly accessible `/construction/parse` endpoint with `signed=true`. This is trivially repeatable using any Hedera SDK.

### Recommendation
Before populating `AccountIdentifierSigners` when `request.Signed = true`, verify that the transaction contains valid signatures from each account being listed. Specifically:

1. Extract the frozen body bytes (as already done in `getFrozenTransactionBodyBytes`).
2. Retrieve the signature map from the deserialized `SignedTransaction`.
3. For each account in `accounts`, verify that a valid Ed25519 signature over the body bytes exists in the signature map from a key associated with that account.
4. Only include accounts with verified signatures in `AccountIdentifierSigners`.

Alternatively, align with the Rosetta spec: when `signed=false`, return required signers from the transaction body; when `signed=true`, return only accounts whose signatures are cryptographically present and valid in the transaction's signature map.

### Proof of Concept

1. Using any Hedera SDK, create an `AccountCreateTransaction` with:
   - `TransactionID.AccountID` = victim's account (e.g., `0.0.12345`)
   - Any valid key in the `key` field
   - Any node account ID
   - Do **not** sign with the victim's key
2. Serialize to bytes and hex-encode.
3. POST to `/construction/parse`:
   ```json
   {
     "network_identifier": { ... },
     "signed": true,
     "transaction": "<hex-encoded-bytes>"
   }
   ```
4. Observe the response:
   ```json
   {
     "account_identifier_signers": [
       { "address": "0.0.12345" }
     ],
     ...
   }
   ```
   The victim account `0.0.12345` is listed as a confirmed signer with no cryptographic proof of consent.

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

**File:** rosetta/app/services/construction_service.go (L198-214)
```go
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
```

**File:** rosetta/app/services/construction_service.go (L658-684)
```go
func unmarshallTransactionFromHexString(transactionString string) (hiero.TransactionInterface, *rTypes.Error) {
	transactionBytes, err := hex.DecodeString(tools.SafeRemoveHexPrefix(transactionString))
	if err != nil {
		return nil, errors.ErrTransactionDecodeFailed
	}

	transaction, err := hiero.TransactionFromBytes(transactionBytes)
	if err != nil {
		return nil, errors.ErrTransactionUnmarshallingFailed
	}

	if rErr := isSupportedTransactionType(transaction); rErr != nil {
		return nil, rErr
	}

	return transaction, nil
}

func isSupportedTransactionType(transaction hiero.TransactionInterface) *rTypes.Error {
	switch transaction.(type) {
	case hiero.AccountCreateTransaction:
	case hiero.TransferTransaction:
	default:
		return errors.ErrTransactionInvalidType
	}

	return nil
```

**File:** rosetta/app/services/construction/crypto_create_transaction_constructor.go (L79-115)
```go
	payer, err := types.NewAccountIdFromSdkAccountId(*cryptoCreateTransaction.GetTransactionID().AccountID)
	if err != nil {
		return nil, nil, errors.ErrInvalidAccount
	}
	metadata := make(map[string]any)
	operation := types.Operation{
		AccountId: payer,
		Amount:    &amount,
		Metadata:  metadata,
		Type:      c.GetOperationType(),
	}

	metadata["memo"] = cryptoCreateTransaction.GetAccountMemo()

	if cryptoCreateTransaction.GetAutoRenewPeriod() != 0 {
		metadata["auto_renew_period"] = int64(cryptoCreateTransaction.GetAutoRenewPeriod().Seconds())
	}

	if key, err := cryptoCreateTransaction.GetKey(); err != nil {
		log.Errorf("Failed to get key from crypto create transaction: %v", err)
		return nil, nil, errors.ErrInvalidTransaction
	} else if key == nil {
		log.Errorf("Key not set for the crypto create transaction")
		return nil, nil, errors.ErrInvalidTransaction
	} else {
		metadata["key"] = key.String()
	}

	if cryptoCreateTransaction.GetMaxAutomaticTokenAssociations() != 0 {
		metadata["max_automatic_token_associations"] = cryptoCreateTransaction.GetMaxAutomaticTokenAssociations()
	}

	if !isZeroAccountId(cryptoCreateTransaction.GetProxyAccountID()) {
		metadata["proxy_account_id"] = cryptoCreateTransaction.GetProxyAccountID().String()
	}

	return types.OperationSlice{operation}, []types.AccountId{payer}, nil
```
