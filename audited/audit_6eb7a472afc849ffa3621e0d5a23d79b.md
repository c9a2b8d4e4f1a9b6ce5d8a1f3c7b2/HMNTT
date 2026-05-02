### Title
`ConstructionParse` Returns Arbitrary Account as `AccountIdentifierSigner` Without Signature Verification

### Summary
`ConstructionParse()` in `rosetta/app/services/construction_service.go` accepts an attacker-supplied transaction hex, delegates to the transaction handler's `Parse()` to extract accounts, and — when `request.Signed=true` — unconditionally promotes every returned account to `AccountIdentifierSigners` with zero cryptographic verification. Because `cryptoCreateTransactionConstructor.Parse()` derives the signer directly from the unauthenticated `TransactionID.AccountID` field in the transaction body, any unprivileged caller can name an arbitrary victim account as a confirmed signer.

### Finding Description

**Exact code path:**

`ConstructionParse()` at [1](#0-0)  decodes the caller-supplied hex, calls `Parse()`, and — with no signature check — promotes every returned account to `AccountIdentifierSigners`:

```go
operations, accounts, err := c.transactionHandler.Parse(ctx, transaction)
...
if request.Signed {
    for _, account := range accounts {
        signers = append(signers, account.ToRosetta())
    }
}
```

`cryptoCreateTransactionConstructor.Parse()` at [2](#0-1)  reads the payer directly from the unauthenticated transaction body field `TransactionID.AccountID` and returns it as the sole signer:

```go
payer, err := types.NewAccountIdFromSdkAccountId(*cryptoCreateTransaction.GetTransactionID().AccountID)
...
return types.OperationSlice{operation}, []types.AccountId{payer}, nil
```

`cryptoTransferTransactionConstructor.Parse()` at [3](#0-2)  similarly derives signers from the transfer amounts in the body, with no signature check.

**Root cause / failed assumption:** The implementation assumes that a transaction presented with `signed=true` has already been verified elsewhere. No such verification exists in this path. The only place where `ed25519.Verify` is called is `ConstructionCombine()` at [4](#0-3) , which is a completely separate endpoint that the attacker never needs to call.

**Why existing checks are insufficient:** `unmarshallTransactionFromHexString()` at [5](#0-4)  only validates that the bytes deserialize into a supported transaction type (`AccountCreateTransaction` or `TransferTransaction`). It does not inspect, require, or validate any signature map entries. The `isSupportedTransactionType` guard at [6](#0-5)  is purely a type check.

### Impact Explanation
Any caller can POST a crafted transaction hex to `/construction/parse` with `signed=true` and receive a response that authoritatively lists an arbitrary victim account under `account_identifier_signers`. Rosetta clients, exchanges, and compliance/monitoring systems that consume this field to determine who has authorized a transaction will be given a false attestation. While the Hedera network itself would reject an actually-unsigned transaction at submission time, the false parse response can be used to deceive off-chain systems (audit logs, multi-party workflow gates, front-end UIs) into believing a victim has consented to a transaction they have never seen.

### Likelihood Explanation
The attack requires no privileges, no credentials, and no on-chain state. The attacker only needs to construct a valid protobuf-encoded `AccountCreateTransaction` or `TransferTransaction` with the victim's account ID in the `TransactionID` field (or as a negative-amount sender in a transfer), hex-encode it, and POST it to the public `/construction/parse` endpoint. This is trivially repeatable and automatable.

### Recommendation
When `request.Signed == true`, verify that the transaction's signature map contains a valid Ed25519 signature from each account before including it in `AccountIdentifierSigners`. Concretely:

1. Extract `frozenBodyBytes` (as already done in `ConstructionCombine`).
2. For each account in the `accounts` slice, look up the corresponding public key and verify its signature against `frozenBodyBytes` using `ed25519.Verify`.
3. Only include accounts whose signatures pass verification in the `signers` slice.
4. Return an error (or omit the account) if `signed=true` but no valid signature is present for a required signer.

### Proof of Concept
```
# 1. Build a valid AccountCreateTransaction protobuf with victim account 0.0.12345
#    as the TransactionID.AccountID payer, a valid new-account key, and any initial balance.
#    Serialize to bytes and hex-encode → TX_HEX

# 2. POST to the mirror-node Rosetta endpoint:
POST /construction/parse
{
  "network_identifier": { "blockchain": "Hedera", "network": "testnet" },
  "signed": true,
  "transaction": "0x<TX_HEX>"
}

# 3. Observe response:
{
  "account_identifier_signers": [
    { "address": "0.0.12345" }   ← victim listed as confirmed signer
  ],
  "operations": [...],
  "metadata": {}
}

# No key material for 0.0.12345 was ever provided or verified.
```

### Citations

**File:** rosetta/app/services/construction_service.go (L82-84)
```go
		if !ed25519.Verify(pubKey.Bytes(), frozenBodyBytes, signature.Bytes) {
			return nil, errors.ErrInvalidSignatureVerification
		}
```

**File:** rosetta/app/services/construction_service.go (L198-208)
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
```

**File:** rosetta/app/services/construction_service.go (L658-674)
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
```

**File:** rosetta/app/services/construction_service.go (L676-685)
```go
func isSupportedTransactionType(transaction hiero.TransactionInterface) *rTypes.Error {
	switch transaction.(type) {
	case hiero.AccountCreateTransaction:
	case hiero.TransferTransaction:
	default:
		return errors.ErrTransactionInvalidType
	}

	return nil
}
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
