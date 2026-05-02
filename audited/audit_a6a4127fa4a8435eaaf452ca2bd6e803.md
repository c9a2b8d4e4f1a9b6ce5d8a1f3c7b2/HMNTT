### Title
Missing `callDataId` Resolution in `addDefaultEthereumTransactionContractResult()` Causes Empty `functionParameters` for Failed Ethereum Transactions with Offloaded Call Data

### Summary
When a failed Ethereum transaction uses the call-data-offloading mechanism (`callDataId` set, inline `callData` null), `addDefaultEthereumTransactionContractResult()` silently substitutes `DomainUtils.EMPTY_BYTE_ARRAY` for `functionParameters` instead of fetching the actual call data from the referenced file. The successful-transaction code path (`EthereumTransactionHandler.updateContractResult()`) correctly resolves `callDataId`, but the failure-path function does not, creating a permanent, incorrect record in the mirror node's `contract_result` table.

### Finding Description

**Vulnerable code path:**

`ContractResultServiceImpl.addDefaultEthereumTransactionContractResult()` — lines 109–112:

```java
var ethereumTransaction = recordItem.getEthereumTransaction();
var functionParameters = ethereumTransaction.getCallData() != null
        ? ethereumTransaction.getCallData()
        : DomainUtils.EMPTY_BYTE_ARRAY;   // ← never resolves callDataId
``` [1](#0-0) 

The function is reached when:
1. The transaction is not a `CONTRACTCALL`/`CONTRACTCREATEINSTANCE` type, AND
2. The `ContractFunctionResult` in the record is the default (empty) instance. [2](#0-1) 

The guard at lines 100–107 only skips `DUPLICATE_TRANSACTION`, `WRONG_NONCE`, and successful transactions — all other failure codes proceed to the buggy assignment. [3](#0-2) 

**Correct code path (not used here):**

`EthereumTransactionHandler.updateContractResult()` — lines 78–92 — correctly handles the offloaded case:

```java
byte[] callData = ethereumTransaction.getCallData();
var callDataId = ethereumTransaction.getCallDataId();
if (ArrayUtils.isEmpty(callData) && !EntityId.isEmpty(callDataId)) {
    callData = contractBytecodeService.get(callDataId);
    ...
}
contractResult.setFunctionParameters(callData != null ? callData : ArrayUtils.EMPTY_BYTE_ARRAY);
``` [4](#0-3) 

The `EthereumTransaction` domain model explicitly supports both `callData` (inline) and `callDataId` (file reference) as mutually exclusive fields: [5](#0-4) 

**Root cause:** `addDefaultEthereumTransactionContractResult()` was written assuming `callData` is always the source of truth, ignoring the protocol-level feature where large call data is offloaded to a Hedera file and referenced via `callDataId`. The failed-transaction branch has no access to `ContractBytecodeService` and no logic to resolve the file reference.

### Impact Explanation

The `contract_result.function_parameters` column is written once and never corrected. Any downstream consumer of the mirror node REST API (`/api/v1/contracts/results/{id}`) will receive `"function_parameters": "0x"` for these transactions instead of the actual ABI-encoded call data. This breaks:
- Transaction replay / debugging tools that reconstruct what was called
- Indexers and analytics that decode function selectors and arguments from `function_parameters`
- The `OpcodeServiceImpl.getCallDataBytes()` fallback path, which reads `contractResult.getFunctionParameters()` when `ethereumTransaction` is null [6](#0-5) 

Severity: **Medium** — data integrity corruption, no fund loss, but permanently incorrect exported records for a well-defined class of transactions.

### Likelihood Explanation

Any unprivileged Hedera account can trigger this:
1. Create a file on Hedera containing ABI call data (standard `FileCreate`/`FileAppend` operations, no special permissions).
2. Submit an `EthereumTransaction` with `callData` FileID set in the body (the `hasCallData()` branch in `EthereumTransactionHandler.doUpdateTransaction()` at line 107–109). [7](#0-6) 

3. Ensure the transaction fails with any status other than `DUPLICATE_TRANSACTION` or `WRONG_NONCE` (e.g., `INSUFFICIENT_GAS`, `INVALID_ACCOUNT_ID`, `CONTRACT_REVERT_EXECUTED`).
4. The mirror node importer processes the record, calls `addDefaultEthereumTransactionContractResult()`, and persists `functionParameters = []`.

This is repeatable, requires no elevated privileges, and costs only normal Hedera transaction fees.

### Recommendation

Mirror `EthereumTransactionHandler.updateContractResult()`'s logic into `addDefaultEthereumTransactionContractResult()`. Inject `ContractBytecodeService` into `ContractResultServiceImpl` and resolve `callDataId` when `callData` is null:

```java
var ethereumTransaction = recordItem.getEthereumTransaction();
byte[] callData = ethereumTransaction.getCallData();
var callDataId = ethereumTransaction.getCallDataId();
if (ArrayUtils.isEmpty(callData) && !EntityId.isEmpty(callDataId)) {
    callData = contractBytecodeService.get(callDataId);
}
var functionParameters = callData != null ? callData : DomainUtils.EMPTY_BYTE_ARRAY;
```

### Proof of Concept

1. **Create call data file:** Submit `FileCreate` + `FileAppend` with payload `0xabcdef01` (any ABI-encoded call).
2. **Submit failing Ethereum transaction:** Construct an `EthereumTransaction` proto with `callData` set to the FileID from step 1 and `ethereumData` containing a valid RLP-encoded transaction targeting a non-existent contract address. Set `maxGasAllowance` low enough to guarantee `INSUFFICIENT_GAS` or target an address that will revert.
3. **Observe importer behavior:** The transaction record will have an empty `ContractFunctionResult` (default instance), routing to `addDefaultEthereumTransactionContractResult()`.
4. **Query mirror node:** `GET /api/v1/contracts/results/{txHash}` — the response will show `"function_parameters": "0x"` instead of `"0xabcdef01"`.
5. **Contrast:** Submit the same transaction successfully (sufficient gas, valid target) — `function_parameters` will correctly contain `"0xabcdef01"` because `EthereumTransactionHandler.updateContractResult()` is used instead.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L99-107)
```java
        var status = recordItem.getTransactionRecord().getReceipt().getStatus();
        if (recordItem.isSuccessful()
                || status == ResponseCodeEnum.DUPLICATE_TRANSACTION
                || status == ResponseCodeEnum.WRONG_NONCE
                || !recordItem.getTransactionBody().hasEthereumTransaction()) {
            // Don't add default contract result for the transaction if it's successful, or the result is
            // DUPLICATE_TRANSACTION, or the result is WRONG_NONCE, or it's not an ethereum transaction
            return;
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L109-112)
```java
        var ethereumTransaction = recordItem.getEthereumTransaction();
        var functionParameters = ethereumTransaction.getCallData() != null
                ? ethereumTransaction.getCallData()
                : DomainUtils.EMPTY_BYTE_ARRAY;
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

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/EthereumTransactionHandler.java (L107-109)
```java
            if (body.hasCallData()) {
                ethereumTransaction.setCallDataId(EntityId.of(body.getCallData()));
            }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/EthereumTransaction.java (L37-40)
```java
    @ToString.Exclude
    private byte[] callData;

    private EntityId callDataId;
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
