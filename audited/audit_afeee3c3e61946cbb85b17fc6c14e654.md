### Title
`failedInitcode` Never Populated for Failed `FILEID`-Based Contract Create Transactions

### Summary
When an unprivileged user submits a `ContractCreateInstance` transaction using `FILEID` as the initcode source and the transaction fails, the mirror node's importer unconditionally leaves `ContractResult.failedInitcode` as `null`. The two code paths that could populate this field both miss the `FILEID` case: the primary path is gated on `InitcodeSourceCase == INITCODE`, and the sidecar fallback path requires a bytecode sidecar record that consensus nodes do not emit for failed deployments. Clients querying `/api/v1/contracts/results/{id}` therefore receive `"failed_initcode": null` even though the initcode was present and identifiable.

### Finding Description

**Primary population path — `ContractCreateTransactionHandler.updateContractResult` (lines 186–188):**

```java
if (!recordItem.isSuccessful() && transactionBody.getInitcodeSourceCase() == INITCODE) {
    contractResult.setFailedInitcode(DomainUtils.toBytes(transactionBody.getInitcode()));
}
```

The condition is `== INITCODE`. When the user chose `FILEID` as the initcode source, `getInitcodeSourceCase()` returns `FILEID`, the branch is skipped, and `failedInitcode` is never set here.

**Sidecar fallback path — `ContractResultServiceImpl.processContractResult` (lines 240–244):**

```java
if (sidecarProcessingResult.initcode() != null
        && !recordItem.isSuccessful()
        && contractResult.getFailedInitcode() == null
        && sidecarProcessingResult.isContractCreation()) {
    contractResult.setFailedInitcode(sidecarProcessingResult.initcode());
}
```

`sidecarProcessingResult.initcode()` is the `payloadBytes` value computed in `processSidecarRecords` (lines 381–434). That value is only assigned when a non-migration bytecode sidecar record is present (`sidecarRecord.hasBytecode() && !migration`, line 412–417). For a **failed** contract deployment, consensus nodes do not emit a bytecode sidecar (the contract was never deployed), so `payloadBytes` stays `null`, the guard `sidecarProcessingResult.initcode() != null` is false, and the fallback is skipped.

**`ContractInitcodeServiceImpl.get` (lines 30–44)** does handle the `FILEID` case (blockstream path), but it is called only from `createContract` inside `ContractCreateTransactionHandler.doUpdateEntity`, which is the entity-persistence path — not from the contract-result path. The result of that call is never routed back to `ContractResult.failedInitcode`.

**End result:** `ContractResult.failedInitcode` is `null` and is persisted as `null` to the database, causing the REST API to return `"failed_initcode": null`.

### Impact Explanation
Any client (developer, tooling, block explorer) that relies on `failed_initcode` to inspect why a contract deployment failed receives no data. The field is documented and exposed in the OpenAPI spec (`rest/api/v1/openapi.yml` lines 2424–2427) as the canonical way to retrieve the initcode of a failed create. For the `FILEID` path the initcode is technically recoverable by separately querying the referenced file, but that requires out-of-band knowledge and extra API calls. The mirror node's exported record is objectively incorrect relative to its own specification.

### Likelihood Explanation
Any unprivileged account on the network can submit a `ContractCreateInstance` with `fileID` set (a standard, widely-used deployment pattern for large contracts). Causing the transaction to fail requires no special privilege — submitting invalid bytecode, setting gas too low, or referencing a non-existent file all produce a failed result. The condition is therefore trivially and repeatably triggerable by any external user.

### Recommendation
In `ContractCreateTransactionHandler.updateContractResult`, extend the `failedInitcode` assignment to also cover the `FILEID` case by reading the initcode via `ContractInitcodeService`:

```java
if (!recordItem.isSuccessful()) {
    if (transactionBody.getInitcodeSourceCase() == INITCODE) {
        contractResult.setFailedInitcode(DomainUtils.toBytes(transactionBody.getInitcode()));
    } else if (transactionBody.getInitcodeSourceCase() == FILEID) {
        // resolve from file; contractInitcodeService already handles this
        byte[] initcode = contractInitcodeService.get(null, recordItem);
        if (initcode != null) {
            contractResult.setFailedInitcode(initcode);
        }
    }
}
```

Alternatively, in `processContractResult`, after `transactionHandler.updateContractResult` returns, add a dedicated fallback that calls `contractInitcodeService.get(null, recordItem)` whenever `failedInitcode` is still null and the transaction is a failed contract create.

### Proof of Concept
1. Upload contract bytecode to a Hedera file (e.g., file `0.0.X`) using `FileCreate` + `FileAppend`.
2. Submit a `ContractCreateInstance` transaction with `fileID = 0.0.X` and a gas limit low enough to guarantee failure (e.g., `gas = 1`).
3. Wait for the transaction to reach consensus and be ingested by the mirror node.
4. Query `GET /api/v1/contracts/results/{transactionId}`.
5. Observe `"failed_initcode": null` in the response, even though the initcode was present in file `0.0.X` and was referenced by the transaction. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/ContractCreateTransactionHandler.java (L186-188)
```java
            if (!recordItem.isSuccessful() && transactionBody.getInitcodeSourceCase() == INITCODE) {
                contractResult.setFailedInitcode(DomainUtils.toBytes(transactionBody.getInitcode()));
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L240-245)
```java
        if (sidecarProcessingResult.initcode() != null
                && !recordItem.isSuccessful()
                && contractResult.getFailedInitcode() == null
                && sidecarProcessingResult.isContractCreation()) {
            contractResult.setFailedInitcode(sidecarProcessingResult.initcode());
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L381-434)
```java
    private SidecarProcessingResult processSidecarRecords(final RecordItem recordItem) {
        final var sidecarRecords = recordItem.getSidecarRecords();
        if (sidecarRecords.isEmpty()) {
            return new SidecarProcessingResult(null, false, null);
        }

        var contractBytecodes = new ArrayList<ContractBytecode>();
        int migrationCount = 0;
        var stopwatch = Stopwatch.createStarted();

        Long topLevelActionSidecarGasUsed = null;
        byte[] payloadBytes = null;
        boolean isContractCreation = false;

        for (final var sidecarRecord : sidecarRecords) {
            final boolean migration = sidecarRecord.getMigration();
            if (sidecarRecord.hasStateChanges()) {
                var stateChanges = sidecarRecord.getStateChanges();
                for (var stateChange : stateChanges.getContractStateChangesList()) {
                    processContractStateChange(migration, recordItem, stateChange);
                }
            } else if (sidecarRecord.hasActions()) {
                var actions = sidecarRecord.getActions();
                for (int actionIndex = 0; actionIndex < actions.getContractActionsCount(); actionIndex++) {
                    final var action = actions.getContractActions(actionIndex);
                    if (action.getCallDepth() == 0) {
                        topLevelActionSidecarGasUsed = action.getGasUsed();
                        isContractCreation = action.getCallType().equals(ContractActionType.CREATE);
                    }
                    processContractAction(action, actionIndex, recordItem);
                }
            } else if (sidecarRecord.hasBytecode()) {
                if (migration) {
                    contractBytecodes.add(sidecarRecord.getBytecode());
                } else {
                    payloadBytes = contractInitcodeService.get(sidecarRecord.getBytecode(), recordItem);
                    isContractCreation = true;
                }
            }
            if (migration) {
                ++migrationCount;
            }
        }

        sidecarContractMigration.migrate(contractBytecodes);
        if (migrationCount > 0) {
            log.info(
                    "{} Sidecar records processed with {} migrations in {}",
                    sidecarRecords.size(),
                    migrationCount,
                    stopwatch);
        }

        return new SidecarProcessingResult(payloadBytes, isContractCreation, topLevelActionSidecarGasUsed);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/service/ContractInitcodeServiceImpl.java (L30-44)
```java
        if (contractCreate.hasInitcode()) {
            return DomainUtils.toBytes(contractCreate.getInitcode());
        } else if (contractCreate.hasFileID() && recordItem.isBlockstream()) {
            final var fileId = EntityId.of(contractCreate.getFileID());
            final byte[] initcode = contractBytecodeService.get(fileId);
            if (initcode == null) {
                Utility.handleRecoverableError(
                        "Failed to get initcode from file {} at {}", fileId, recordItem.getConsensusTimestamp());
                return null;
            }

            final var constructorParameters = contractCreate.getConstructorParameters();
            return constructorParameters.isEmpty()
                    ? initcode
                    : Bytes.concat(initcode, DomainUtils.toBytes(constructorParameters));
```
