The code has been verified. The bug is real and confirmed. Here is the audit report:

---

Audit Report

## Title
Wrong `getContractCallResult()` Used When Parent Is `ContractCreate` — Synthetic Log Persisted With `EntityId.EMPTY` Contract ID

## Summary
In `SyntheticContractLogServiceImpl.create()`, the `if` condition at line 55 correctly guards on `hasContractCallResult() || hasContractCreateResult()`, but the true-branch body unconditionally calls `getContractCallResult().getContractID()` regardless of which branch was true. When the parent transaction is a `ContractCreate` (only `hasContractCreateResult()` is set), `getContractCallResult()` returns a default-initialized empty protobuf message, causing `getContractID()` to yield `ContractID{0,0,0}`, which resolves to `EntityId.EMPTY`. The resulting `ContractLog` is persisted with `contractId = 0`, silently corrupting all contract-specific log queries for that contract.

## Finding Description

**Exact location:** `importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticContractLogServiceImpl.java`, lines 54–60:

```java
final var parentTransactionRecord = contractRelatedParentRecordItem.getTransactionRecord();
if (parentTransactionRecord.hasContractCallResult() || parentTransactionRecord.hasContractCreateResult()) {
    contractId = EntityId.of(
            parentTransactionRecord.getContractCallResult().getContractID()); // BUG: always reads CallResult
} else {
    contractId = EntityId.EMPTY;
}
``` [1](#0-0) 

**Root cause:** The `||` disjunction in the guard means the true-branch is entered whenever either result is present. However, the body hard-codes `getContractCallResult()`. When the parent record has only `contractCreateResult` set (a `ContractCreate` transaction), `getContractCallResult()` returns a default-initialized (all-zero) protobuf `ContractFunctionResult`. Its `getContractID()` returns `ContractID{shard=0, realm=0, contractNum=0}`.

**EntityId resolution chain:**
- `EntityId.of(ContractID)` → `of(shard=0, realm=0, num=0)` [2](#0-1) 
- `of(0, 0, 0)` → `encode(0, 0, 0)` = `0L` → `of(0L)` [3](#0-2) 
- `of(0L)` returns `EMPTY` (the singleton for `id == 0`) [4](#0-3) 

The corrupted `contractId` is then set on the `ContractLog` and persisted via `entityListener.onContractLog(contractLog)`. [5](#0-4) 

**Why existing guards do not prevent this:** `shouldSkipLogCreation()` only filters on HAPI version and multi-party transfer count. It does not prevent the wrong result-type read. The `else` branch (`contractId = EntityId.EMPTY`) is never reached in this scenario because the `||` condition is already `true` — the bug is inside the true-branch. [6](#0-5) 

## Impact Explanation
Every synthetic Transfer log emitted by a token mint or transfer triggered from a `ContractCreate` constructor is stored with `contractId = 0` instead of the deploying contract's actual ID. REST API endpoints that filter `contract_log` by `contractId` (e.g., `GET /api/v1/contracts/{id}/results/logs`) will silently omit these logs. Indexers, block explorers, and dApps relying on the mirror node for ERC-20/HTS Transfer event history for factory-pattern contracts will receive permanently incomplete data. The records are committed to the DB with the wrong ID and cannot be corrected without a re-import.

## Likelihood Explanation
The trigger is a completely standard, unprivileged Hedera operation: deploying a contract whose constructor mints tokens. This is a common pattern for ERC-20-style token factory contracts. No special permissions, keys, or network access beyond a funded account are required. The bug fires deterministically on every such deployment on HAPI versions < 0.71.0 (where synthetic log creation is active). It is silently repeatable.

## Recommendation
Replace the single `if` branch with an explicit check for which result type is present:

```java
if (parentTransactionRecord.hasContractCallResult()) {
    contractId = EntityId.of(
            parentTransactionRecord.getContractCallResult().getContractID());
} else if (parentTransactionRecord.hasContractCreateResult()) {
    contractId = EntityId.of(
            parentTransactionRecord.getContractCreateResult().getContractID());
} else {
    contractId = EntityId.EMPTY;
}
```

This mirrors the same pattern already used correctly for `rootContractId` resolution at lines 62–71, where `hasContractCall()` is checked on the transaction body before reading the appropriate field. [7](#0-6) 

## Proof of Concept
1. Submit a `ContractCreate` transaction whose constructor calls the HTS precompile to mint fungible tokens.
2. The consensus node produces a record stream where the `ContractCreate` record has `contractCreateResult` set (not `contractCallResult`), and the child `TokenMint` record has `parentConsensusTimestamp` pointing to the `ContractCreate`.
3. The mirror node importer resolves `getContractRelatedParent()` on the `TokenMint` `RecordItem` to the `ContractCreate` parent.
4. `SyntheticContractLogServiceImpl.create()` is called for the synthetic Transfer log of the mint.
5. Line 55: `hasContractCreateResult()` = `true` → enters if-branch.
6. Line 57: `getContractCallResult().getContractID()` = `ContractID{0,0,0}` → `contractId = EntityId.EMPTY`.
7. `ContractLog` is persisted with `contractId = 0`.
8. Query `GET /api/v1/contracts/{actual-contract-id}/results/logs` — the Transfer log is absent. Query `GET /api/v1/contracts/0.0.0/results/logs` — the Transfer log appears under the zero address instead.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticContractLogServiceImpl.java (L54-60)
```java
            final var parentTransactionRecord = contractRelatedParentRecordItem.getTransactionRecord();
            if (parentTransactionRecord.hasContractCallResult() || parentTransactionRecord.hasContractCreateResult()) {
                contractId = EntityId.of(
                        parentTransactionRecord.getContractCallResult().getContractID());
            } else {
                contractId = EntityId.EMPTY;
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticContractLogServiceImpl.java (L62-71)
```java
            final var parentTransactionBody = contractRelatedParentRecordItem.getTransactionBody();
            if (parentTransactionBody.hasContractCall()) {
                final var contractIdReceipt =
                        parentTransactionRecord.getReceipt().getContractID();

                rootContractId = EntityId.of(contractIdReceipt);
            } else {
                rootContractId =
                        EntityId.of(parentTransactionRecord.getReceipt().getContractID());
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticContractLogServiceImpl.java (L85-98)
```java
        contractLog.setContractId(contractId);
        contractLog.setData(log.getData() != null ? log.getData() : empty);
        contractLog.setIndex(logIndex);
        contractLog.setRootContractId(rootContractId);
        contractLog.setPayerAccountId(recordItem.getPayerAccountId());
        contractLog.setTopic0(log.getTopic0());
        contractLog.setTopic1(log.getTopic1());
        contractLog.setTopic2(log.getTopic2());
        contractLog.setTopic3(log.getTopic3());
        contractLog.setTransactionIndex(transactionIndex);
        contractLog.setTransactionHash(transactionHash);
        contractLog.setSynthetic(log instanceof TransferContractLog);

        entityListener.onContractLog(contractLog);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticContractLogServiceImpl.java (L106-126)
```java
    private boolean shouldSkipLogCreation(SyntheticContractLog syntheticLog) {
        final var contractOrigin = isContract(syntheticLog.getRecordItem());
        if (contractOrigin && !(syntheticLog instanceof TransferContractLog)) {
            // Only TransferContractLog synthetic log creation is supported for an operation with contract origin
            return true;
        }

        final var recordItem = syntheticLog.getRecordItem();

        final var tokenTransfersCount = recordItem.getTransactionRecord().getTokenTransferListsCount();
        if (tokenTransfersCount > 2 && !entityProperties.getPersist().isSyntheticContractLogsMulti()) {
            // We have a multi-party fungible transfer scenario and synthetic event creation for
            // such transfers is disabled. We should skip this case no matter if the log is from HAPI or contract
            // origin.
            return true;
        }

        // Skip synthetic log creation for events with contract origin with HAPI versions >= 0.71.0 as the logs are
        // already imported by consensus nodes. We should create logs for events with HAPI origin for any HAPI version.
        return contractOrigin && recordItem.getHapiVersion().isGreaterThanOrEqualTo(HAPI_SYNTHETIC_LOG_VERSION);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L91-93)
```java
    public static EntityId of(ContractID contractID) {
        return of(contractID.getShardNum(), contractID.getRealmNum(), contractID.getContractNum());
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L137-140)
```java
    public static EntityId of(long shard, long realm, long num) {
        long id = encode(shard, realm, num);
        return of(id);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L142-145)
```java
    public static EntityId of(long id) {
        if (id == 0) {
            return EMPTY;
        }
```
