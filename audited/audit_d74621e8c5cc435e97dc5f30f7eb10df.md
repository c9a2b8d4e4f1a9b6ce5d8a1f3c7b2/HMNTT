### Title
Incorrect `from` Address in Contract Results for Failed Sponsored Ethereum Transactions

### Summary
In `ContractResultServiceImpl.addDefaultEthereumTransactionContractResult`, when a sponsored Ethereum transaction fails before EVM execution (producing no `ContractFunctionResult`), `senderId` is unconditionally set to `payerAccountId` rather than the actual ECDSA-derived EVM sender. The mirror node then exports this incorrect value as the `from` field in the contract result, permanently misleading any client querying the REST API about the true originator of the call.

### Finding Description

**Exact code path:**

In `ContractResultServiceImpl.process()`, the routing condition at lines 72–77 sends any `ETHEREUMTRANSACTION` that lacks a populated `ContractFunctionResult` to `addDefaultEthereumTransactionContractResult`: [1](#0-0) 

Inside that method, `senderId` is hardcoded to `payerAccountId` with no attempt to recover the actual EVM signer from the Ethereum transaction's ECDSA signature components (`signatureR`, `signatureS`, `recoveryId`): [2](#0-1) 

**Contrast with the successful path:** `processContractResult` also defaults `senderId` to `payerAccountId` but then overrides it with the consensus-node-supplied `functionResult.getSenderId()` when present: [3](#0-2) 

For early-failed transactions, no `ContractFunctionResult` is produced by the consensus node, so the override never happens and the payer is permanently stored as the sender.

**REST API exposure:** `ContractResultViewModel` derives the public `from` field directly from `senderId`: [4](#0-3) 

**Root cause:** The `EthereumTransaction` domain object already holds `signatureR`, `signatureS`, and `recoveryId`: [5](#0-4) 

The infrastructure to recover an EVM address from these components exists in `Utility.recoverAddressFromPubKey` and is used elsewhere in the codebase, but `addDefaultEthereumTransactionContractResult` never calls it. [6](#0-5) 

### Impact Explanation
Any client (block explorer, DeFi analytics, audit system, compliance tool) querying `/api/v1/contracts/results/{hash}` for a failed sponsored Ethereum transaction will receive a `from` address belonging to the gas relayer/payer rather than the actual EVM signer. This permanently corrupts the on-chain attribution record stored in the mirror node database. For sponsored-transaction workflows (common in account-abstraction and gas-relay patterns), every pre-execution failure produces a falsified originator record. There is no mechanism for clients to detect or correct this after the fact.

### Likelihood Explanation
The precondition — payer ≠ EVM signer — is the normal operating mode for any sponsored/relayed Ethereum transaction on Hedera. Triggering a pre-execution failure (e.g., `INSUFFICIENT_GAS`, `INVALID_ACCOUNT_ID`, `INSUFFICIENT_PAYER_BALANCE`, `INVALID_ETHEREUM_TRANSACTION`) requires no privilege and is trivially achievable by any user, intentionally or accidentally. The scenario is repeatable at will and affects all historical records already written under this code path.

### Recommendation
In `addDefaultEthereumTransactionContractResult`, after decoding the `EthereumTransaction`, recover the actual EVM sender address from `signatureR`, `signatureS`, and `recoveryId` (using the existing ECDSA recovery infrastructure in `Utility`/`EthSigsUtils`), look up the corresponding `EntityId` via `EntityIdService`, and use that as `senderId`. Fall back to `payerAccountId` only if recovery fails. This mirrors what the consensus node does when it populates `ContractFunctionResult.senderId` for successful transactions.

### Proof of Concept
1. Create two Hedera accounts: **Relayer** (`0.0.1000`, EVM address `0xAAAA…`) and **Signer** (ECDSA key, EVM address `0xBBBB…`).
2. Construct a valid EIP-1559 Ethereum transaction signed by **Signer**'s private key, targeting any contract, with a gas limit deliberately set below the minimum (e.g., `1`).
3. Submit the transaction to Hedera with **Relayer** as the Hedera payer.
4. The consensus node rejects it with `INSUFFICIENT_GAS` and emits no `ContractFunctionResult`.
5. The mirror node importer calls `addDefaultEthereumTransactionContractResult`, writing `sender_id = 0.0.1000` (Relayer) to the `contract_result` table.
6. Query `GET /api/v1/contracts/results/{ethereumHash}` — the response contains `"from": "0x000…aaaa"` (Relayer's address) instead of the correct `"from": "0x000…bbbb"` (Signer's address).

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L72-77)
```java
        boolean contractCallOrCreate = isContractCreateOrCall(transaction);
        if (!contractCallOrCreate && !isContractFunctionResultSet(functionResult)) {
            addDefaultEthereumTransactionContractResult(recordItem, transaction);
            // skip any other transaction which is neither a create/call and has no valid ContractFunctionResult
            return;
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L113-127)
```java
        var payerAccountId = transaction.getPayerAccountId();
        var contractResult = ContractResult.builder()
                .callResult(DomainUtils.EMPTY_BYTE_ARRAY)
                .consensusTimestamp(transaction.getConsensusTimestamp())
                .contractId(0)
                .functionParameters(functionParameters)
                .gasLimit(ethereumTransaction.getGasLimit())
                .gasUsed(0L)
                .payerAccountId(payerAccountId)
                .senderId(payerAccountId)
                .transactionHash(ethereumTransaction.getHash())
                .transactionIndex(transaction.getIndex())
                .transactionNonce(transaction.getNonce())
                .transactionResult(transaction.getResult())
                .build();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L232-260)
```java
        // senderId defaults to payerAccountId
        contractResult.setSenderId(payerAccountId);
        contractResult.setTransactionHash(transactionHash);
        contractResult.setTransactionIndex(transaction.getIndex());
        contractResult.setTransactionNonce(transaction.getNonce());
        contractResult.setTransactionResult(transaction.getResult());
        transactionHandler.updateContractResult(contractResult, recordItem);

        if (sidecarProcessingResult.initcode() != null
                && !recordItem.isSuccessful()
                && contractResult.getFailedInitcode() == null
                && sidecarProcessingResult.isContractCreation()) {
            contractResult.setFailedInitcode(sidecarProcessingResult.initcode());
        }

        if (isContractFunctionResultSet(functionResult)) {
            contractResult.setBloom(DomainUtils.toBytes(functionResult.getBloom()));
            contractResult.setCallResult(DomainUtils.toBytes(functionResult.getContractCallResult()));
            contractResult.setCreatedContractIds(contractIds);
            contractResult.setErrorMessage(functionResult.getErrorMessage());
            contractResult.setFunctionResult(functionResult.toByteArray());
            contractResult.setGasUsed(functionResult.getGasUsed());
            updateGasConsumed(contractResult, sidecarProcessingResult, recordItem);

            if (functionResult.hasSenderId()) {
                var senderId = EntityId.of(functionResult.getSenderId());
                contractResult.setSenderId(senderId);
                recordItem.addEntityId(senderId);
            }
```

**File:** rest/viewmodel/contractResultViewModel.js (L38-40)
```javascript
    this.from =
      EntityId.parse(contractResult.senderId, {isNullable: true}).toEvmAddress() ||
      this.#extractSenderFromFunctionResult(contractResult);
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/EthereumTransaction.java (L73-85)
```java
    private Integer recoveryId;

    @Column(name = "signature_r")
    @ToString.Exclude
    private byte[] signatureR;

    @Column(name = "signature_s")
    @ToString.Exclude
    private byte[] signatureS;

    @Column(name = "signature_v")
    @ToString.Exclude
    private byte[] signatureV;
```

**File:** importer/src/main/java/org/hiero/mirror/importer/util/Utility.java (L233-252)
```java
    // This method is copied from consensus node's EthTxSigs::recoverAddressFromPubKey and should be kept in sync
    @SuppressWarnings("java:S1168")
    private static byte[] recoverAddressFromPubKey(byte[] pubKeyBytes) {
        final var point = EC_DOMAIN_PARAMETERS.getCurve().decodePoint(pubKeyBytes);

        if (!point.isValid()) {
            throw new IllegalArgumentException("Invalid public key: point is not on the secp256k1 curve");
        }

        final var uncompressed = point.normalize().getEncoded(false);
        final var raw64 = Arrays.copyOfRange(uncompressed, 1, 65);

        final var digest = new KeccakDigest(256);
        digest.update(raw64, 0, raw64.length);

        final var hash = new byte[32];
        digest.doFinal(hash, 0);

        return Arrays.copyOfRange(hash, 12, 32);
    }
```
