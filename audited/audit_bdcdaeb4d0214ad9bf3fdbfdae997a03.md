### Title
`ConstructionParse()` Silently Ignores Token Transfers in `TransferTransaction`, Enabling Hidden Operation Injection

### Summary
The `Parse()` method in `cryptoTransferTransactionConstructor` only reads HBAR transfers via `GetHbarTransfers()`, completely ignoring fungible token and NFT transfers that the Hiero SDK's `TransferTransaction` supports in the same transaction. An attacker can craft a `TransferTransaction` embedding hidden token/NFT transfers alongside visible HBAR transfers; `ConstructionParse()` returns only the HBAR operations, while the network and mirror node record the full transaction including the hidden transfers.

### Finding Description

**Code path:**

`ConstructionParse()` at [1](#0-0)  calls `c.transactionHandler.Parse()`, which dispatches to `cryptoTransferTransactionConstructor.Parse()`.

Inside that method, only `GetHbarTransfers()` is called: [2](#0-1) 

`GetTokenTransfers()` and `GetNftTransfers()` are never called. The operations slice is sized and populated exclusively from the HBAR transfer map.

**Gate check — `isSupportedTransactionType()`:** [3](#0-2) 

This check only validates the Go type of the transaction (`hiero.TransferTransaction`). A `TransferTransaction` that also carries token/NFT transfers is still a `hiero.TransferTransaction` and passes this check without any content inspection.

**Root cause:** The code assumes a `TransferTransaction` accepted by the Rosetta endpoint can only contain HBAR transfers. The Hiero SDK's `TransferTransaction` is a multi-asset transfer primitive that supports HBAR, fungible tokens, and NFTs in a single atomic transaction. The `Parse()` implementation never reads the non-HBAR transfer lists, so they are invisible to the Rosetta layer but fully recorded on-chain and by the mirror node.

**Exploit flow:**
1. Attacker constructs a raw `TransferTransaction` (outside the Rosetta flow) containing:
   - A small HBAR transfer (e.g., −1 tinybar from victim → attacker) — *visible to Parse*
   - A large token transfer (e.g., −1 000 000 tokens from victim → attacker) — *invisible to Parse*
2. Attacker hex-encodes the transaction and presents it to the victim (e.g., as the `unsigned_transaction` in a Rosetta workflow).
3. Victim calls `POST /construction/parse` with the crafted hex. Response contains only the HBAR operation.
4. Victim believes the transaction is a trivial HBAR transfer, signs it, and calls `POST /construction/submit`.
5. The network executes the full transaction; the mirror node records both the HBAR transfer and the token transfer.

### Impact Explanation
A victim who relies on `ConstructionParse()` as the verification step before signing (the standard Rosetta Construction API pattern) can be tricked into authorizing token/NFT transfers they never consented to. The mirror node faithfully records the complete on-chain state, which diverges from what the Rosetta parse response showed. For exchanges or wallets that use this Rosetta implementation, this enables silent asset theft with a single crafted transaction.

### Likelihood Explanation
No privilege is required. The attacker only needs to produce a valid serialized `TransferTransaction` using the public Hiero SDK, which is trivial. The victim must be using the Rosetta `/construction/parse` endpoint for pre-signing verification — the exact use case the endpoint is designed for. The attack is fully repeatable and requires no on-chain state or special account permissions.

### Recommendation
In `cryptoTransferTransactionConstructor.Parse()`, after reading HBAR transfers, also read and surface token and NFT transfers:

```go
// After the existing HBAR loop:
for tokenId, tokenTransfers := range transferTransaction.GetTokenTransfers() {
    for accountId, amount := range tokenTransfers {
        // build a token Amount and call c.addOperation(...)
    }
}
for tokenId, nftTransfers := range transferTransaction.GetNftTransfers() {
    // build NFT operations similarly
}
```

Additionally, add a guard in `isSupportedTransactionType()` (or in `ConstructionParse()` itself) that rejects any `TransferTransaction` containing token or NFT transfers until full support is implemented, preventing the parse/submit discrepancy entirely.

### Proof of Concept

```go
// Attacker-side: craft the malicious transaction
tx := hiero.NewTransferTransaction().
    AddHbarTransfer(victimAccountId, hiero.HbarFromTinybar(-1)).
    AddHbarTransfer(attackerAccountId, hiero.HbarFromTinybar(1)).
    AddTokenTransfer(tokenId, victimAccountId, -1_000_000).
    AddTokenTransfer(tokenId, attackerAccountId, 1_000_000).
    SetTransactionID(hiero.TransactionIDGenerate(victimAccountId)).
    SetNodeAccountIDs([]hiero.AccountID{nodeAccountId})
tx.Freeze()
txBytes, _ := hiero.TransactionToBytes(tx)
hexTx := hex.EncodeToString(txBytes)

// POST /construction/parse  { "transaction": hexTx, "signed": false }
// Response operations: only the -1 / +1 tinybar HBAR transfer — token transfer absent.

// Victim signs hexTx and calls POST /construction/submit.
// Network executes: HBAR transfer + 1,000,000 token transfer.
// Mirror node records both; Rosetta parse showed only one.
```

### Citations

**File:** rosetta/app/services/construction_service.go (L183-214)
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

**File:** rosetta/app/services/construction/crypto_transfer_transaction_constructor.go (L68-78)
```go
	hbarTransferMap := transferTransaction.GetHbarTransfers()
	numOperations := len(hbarTransferMap)
	operations := make(types.OperationSlice, 0, numOperations)

	for accountId, hbarAmount := range hbarTransferMap {
		var err *rTypes.Error
		amount := &types.HbarAmount{Value: hbarAmount.AsTinybar()}
		if operations, err = c.addOperation(accountId, amount, operations); err != nil {
			return nil, nil, err
		}
	}
```
