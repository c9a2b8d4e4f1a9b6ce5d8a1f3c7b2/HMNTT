### Title
Offloaded-Calldata Ethereum Transactions Replayed with Empty Input, Producing Fabricated Opcode Traces

### Summary
When an Ethereum transaction's calldata was offloaded to a Hedera file (a supported protocol feature for large calldata), `OpcodeServiceImpl.getEthereumDataBytes()` feeds the replay engine the stored raw RLP bytes that contain an **empty** calldata field (`0x80`), while `getCallDataBytes()` also returns an empty array and is ignored anyway. The EVM re-executes the transaction with zero input, producing an opcode trace that is entirely different from the original on-chain execution. Any unprivileged user can trigger this by supplying the hash of any such historical transaction to `GET /api/v1/contracts/results/{hash}/opcodes`.

### Finding Description

**Confirmed DB state for offloaded-calldata transactions** (proven by the integration test at `EntityRecordItemListenerEthereumTest.java` lines 226–227):

```
ethereumTransaction.getCallData()   → EMPTY_BYTE_ARRAY
ethereumTransaction.getData()       → RAW_TX_TYPE_1_CALL_DATA_OFFLOADED  (RLP with "80" = empty calldata)
ethereumTransaction.getCallDataId() → <file entity ID holding the real calldata>
```

**Replay code path:**

`OpcodeServiceImpl.buildCallServiceParameters()` (lines 165–175) assembles `ContractDebugParameters` with:

```java
.callData(getCallDataBytes(ethTransaction, contractResult))   // → []  (empty)
.ethereumData(getEthereumDataBytes(ethTransaction))           // → RLP with empty calldata field
```

`getEthereumDataBytes()` (lines 228–234) blindly returns `ethereumTransaction.getData()` — the offloaded-variant RLP — without checking `callDataId` or reconstructing the full transaction:

```java
private byte[] getEthereumDataBytes(EthereumTransaction ethereumTransaction) {
    final var data = ethereumTransaction.getData();
    return data != null ? data : new byte[0];
}
```

`getCallDataBytes()` (lines 221–226) returns `ethereumTransaction.getCallData()` which is `EMPTY_BYTE_ARRAY` for offloaded transactions. It never checks `callDataId` (unlike `EthereumTransactionHandler.updateContractResult()` lines 78–92 which correctly loads from file).

`TransactionExecutionService.execute()` (lines 82–85) then takes the ethereum-transaction branch because `ethereumData.length > 0`, and `callData` is **never consulted**:

```java
if (params instanceof ContractDebugParameters debugParams
        && debugParams.getEthereumData() != null
        && debugParams.getEthereumData().length > 0) {
    transactionBody = buildEthereumTransactionBody(debugParams);   // uses only ethereumData
}
```

`buildEthereumTransactionBody()` (lines 201–212) wraps the offloaded-variant RLP directly as `ethereumData` and submits it to the executor. The EVM receives a transaction with an empty `data` field and executes accordingly — a completely different code path than the original.

**Contrast with the correct pattern:** `AbstractEthereumTransactionParser.getHash()` (lines 29–63) explicitly detects the offloaded case (`callData` empty + `callDataId` non-empty), loads the real calldata from the file, re-encodes the full RLP, and then hashes it. The replay path performs no equivalent reconstruction.

**No authentication gate:** `OpcodesController.getContractOpcodes()` (lines 52–68) has no `@PreAuthorize` or any other access control; the only guards are a feature-flag check and a `gzip` header requirement, both trivially satisfied by any caller.

### Impact Explanation
For every historical Ethereum transaction whose calldata was offloaded to a Hedera file, the opcode endpoint returns a trace that reflects execution of an **empty-input call** rather than the actual transaction. The fabricated trace will show a different sequence of opcodes, different SLOAD/SSTORE operations, different return data, and a different success/failure outcome. This directly undermines the integrity of the historical record exposed by the mirror node: auditors, investigators, and tooling that rely on opcode traces to reconstruct what a contract did will receive false evidence. Because the endpoint is unauthenticated, the attack surface is the entire public internet.

### Likelihood Explanation
Offloaded calldata is a documented, production-used Hedera feature (evidenced by testnet data in the test suite). Any attacker who can enumerate transaction hashes — trivially done via the public mirror-node REST API — can identify qualifying transactions and repeatedly trigger misleading traces. No special account, key, or privilege is required. The attack is fully repeatable and stateless.

### Recommendation
In `OpcodeServiceImpl.buildCallServiceParameters()`, apply the same offloaded-calldata reconstruction logic that `EthereumTransactionHandler.updateContractResult()` already uses: when `ethereumTransaction.getCallData()` is empty and `ethereumTransaction.getCallDataId()` is non-empty, load the real calldata from the file store, then re-encode the full RLP (mirroring `AbstractEthereumTransactionParser.getHash()` lines 41–58) before setting `ethereumData`. Alternatively, inject a reference to `EthereumTransactionParser` into `OpcodeServiceImpl` and call `getHash`-style re-encoding to produce the correct `ethereumData` bytes. Add an integration test that persists a transaction with offloaded calldata and asserts the returned opcode trace matches the expected execution of the real calldata.

### Proof of Concept
1. Identify a historical Ethereum transaction on mainnet/testnet where calldata was offloaded (query `ethereum_transaction` table for rows where `call_data` is empty and `call_data_id` is non-null, or use the public REST API `/api/v1/contracts/results?limit=100` and filter for entries with a non-null `call_data_id`).
2. Note the transaction hash, e.g. `0x4a563af33c4871b51a8b108aa2fe1dd5280a30dfb7236170ae5e5e7957eb6392`.
3. Issue:
   ```
   GET /api/v1/contracts/results/0x4a563af33c4871b51a8b108aa2fe1dd5280a30dfb7236170ae5e5e7957eb6392/opcodes
   Accept-Encoding: gzip
   ```
4. Observe the returned opcode trace. The `opcodes` array will reflect execution of an empty-input call (e.g., hitting the contract's fallback/receive function or reverting immediately) rather than the actual function that was originally invoked.
5. Compare against the `function_parameters` field returned by `/api/v1/contracts/results/{hash}` (which correctly shows the real calldata loaded from the file) to confirm the divergence. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L165-175)
```java
        return ContractDebugParameters.builder()
                .block(blockType)
                .callData(getCallDataBytes(ethTransaction, contractResult))
                .ethereumData(getEthereumDataBytes(ethTransaction))
                .consensusTimestamp(consensusTimestamp)
                .gas(getGasLimit(ethTransaction, contractResult))
                .receiver(getReceiverAddress(ethTransaction, contractResult, transactionType))
                .sender(getSenderAddress(contractResult))
                .value(getValue(ethTransaction, contractResult).longValue())
                .build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L221-226)
```java
    private byte[] getCallDataBytes(EthereumTransaction ethereumTransaction, ContractResult contractResult) {
        final var callData = ethereumTransaction != null
                ? ethereumTransaction.getCallData()
                : contractResult.getFunctionParameters();
        return callData != null ? callData : new byte[0];
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L228-234)
```java
    private byte[] getEthereumDataBytes(EthereumTransaction ethereumTransaction) {
        if (ethereumTransaction == null) {
            return new byte[0];
        }
        final var data = ethereumTransaction.getData();
        return data != null ? data : new byte[0];
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L82-85)
```java
        if (params instanceof ContractDebugParameters debugParams
                && debugParams.getEthereumData() != null
                && debugParams.getEthereumData().length > 0) {
            transactionBody = buildEthereumTransactionBody(debugParams);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/TransactionExecutionService.java (L201-212)
```java
    private TransactionBody buildEthereumTransactionBody(final ContractDebugParameters params) {
        final var txnBody = defaultTransactionBodyBuilder(params)
                .ethereumTransaction(EthereumTransactionBody.newBuilder()
                        .ethereumData(Bytes.wrap(params.getEthereumData()))
                        .maxGasAllowance(Long.MAX_VALUE)
                        .build())
                .transactionFee(CONTRACT_CREATE_TX_FEES)
                .build();

        patchSenderNonce(params);
        return txnBody;
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/EthereumTransactionHandler.java (L78-92)
```java
        byte[] callData = ethereumTransaction.getCallData();
        var callDataId = ethereumTransaction.getCallDataId();
        if (ArrayUtils.isEmpty(callData) && !EntityId.isEmpty(callDataId)) {
            // call data file (callDataId) is ignored by consensus node if there's call data in ethereum data
            callData = contractBytecodeService.get(callDataId);
            if (callData == null) {
                Utility.handleRecoverableError(
                        "Failed to read call data from file {} for ethereum transaction at {}",
                        callDataId,
                        recordItem.getConsensusTimestamp());
            }
        }

        // #12199, function_parameters is a not-null db column, so set it to an empty array as fallback
        contractResult.setFunctionParameters(callData != null ? callData : ArrayUtils.EMPTY_BYTE_ARRAY);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/ethereum/AbstractEthereumTransactionParser.java (L37-58)
```java
        if (ArrayUtils.isNotEmpty(callData) || EntityId.isEmpty(callDataId)) {
            return getHash(transactionBytes);
        }

        try {
            var ethereumTransaction = decode(transactionBytes);
            if (ArrayUtils.isNotEmpty(ethereumTransaction.getAccessList())) {
                log.warn("Re-encoding ethereum transaction at {} with access list is unsupported", consensusTimestamp);
                return EMPTY_BYTE_ARRAY;
            }

            callData = getCallData(callDataId, consensusTimestamp, useCurrentState);
            if (callData == null) {
                Utility.handleRecoverableError(
                        "Failed to read call data from file {} for ethereum transaction at {}",
                        callDataId,
                        consensusTimestamp);
                return EMPTY_BYTE_ARRAY;
            }

            ethereumTransaction.setCallData(callData);
            return getHash(encode(ethereumTransaction));
```

**File:** importer/src/test/java/org/hiero/mirror/importer/parser/record/entity/EntityRecordItemListenerEthereumTest.java (L221-229)
```java
        softly.assertThat(ethereumTransactionRepository.findAll())
                .hasSize(1)
                .first()
                .returns(consensusTimestamp, EthereumTransaction::getConsensusTimestamp)
                .returns(fileId, EthereumTransaction::getCallDataId)
                .returns(EMPTY_BYTE_ARRAY, EthereumTransaction::getCallData)
                .returns(RAW_TX_TYPE_1_CALL_DATA_OFFLOADED, EthereumTransaction::getData)
                .returns(expectedHash, EthereumTransaction::getHash)
                .returns(body.getMaxGasAllowance(), EthereumTransaction::getMaxGasAllowance);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/OpcodesController.java (L52-68)
```java
    @GetMapping(value = "/{transactionIdOrHash}/opcodes")
    OpcodesResponse getContractOpcodes(
            @PathVariable TransactionIdOrHashParameter transactionIdOrHash,
            @RequestParam(required = false, defaultValue = "true") boolean stack,
            @RequestParam(required = false, defaultValue = "false") boolean memory,
            @RequestParam(required = false, defaultValue = "false") boolean storage,
            @RequestHeader(value = HttpHeaders.ACCEPT_ENCODING) String acceptEncoding) {
        if (properties.isEnabled()) {
            validateAcceptEncodingHeader(acceptEncoding);
            throttleManager.throttleOpcodeRequest();

            final var request = new OpcodeRequest(transactionIdOrHash, stack, memory, storage);
            return opcodeService.processOpcodeCall(request);
        }

        throw new ResponseStatusException(HttpStatus.NOT_FOUND);
    }
```
