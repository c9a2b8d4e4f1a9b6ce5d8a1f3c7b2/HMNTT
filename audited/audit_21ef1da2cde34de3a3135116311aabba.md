### Title
Silent Fallback to `BlockType.LATEST` in Opcode Replay Produces Historically Inaccurate EVM Trace

### Summary
In `OpcodeServiceImpl.buildCallServiceParameters()`, when `recordFileService.findByTimestamp()` returns empty for a given `consensusTimestamp`, the code silently falls back to `BlockType.LATEST` instead of throwing an error. Because `ContractCallContext.useHistorical()` returns `false` for `BlockType.LATEST`, all downstream state reads (storage, balances, bytecode) are performed against the **current** database state rather than the historical state at the time of the original transaction, producing an opcode trace that misrepresents the original execution.

### Finding Description

**Exact code path:**

`OpcodeServiceImpl.java`, `buildCallServiceParameters(Long, Transaction, EthereumTransaction)`, lines 158–161:

```java
final var blockType = recordFileService
        .findByTimestamp(consensusTimestamp)
        .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
        .orElse(BlockType.LATEST);   // ← silent fallback
``` [1](#0-0) 

`ContractCallContext.useHistorical()` gates every historical state read:

```java
public boolean useHistorical() {
    return callServiceParameters != null && callServiceParameters.getBlock() != BlockType.LATEST;
}
``` [2](#0-1) 

When `useHistorical()` is `false`, `getTimestamp()` returns `Optional.empty()`:

```java
public Optional<Long> getTimestamp() {
    if (useHistorical()) {
        return getTimestampOrDefaultFromRecordFile();
    }
    return Optional.empty();   // ← no historical timestamp pinned
}
``` [3](#0-2) 

Every KV-state reader (e.g., `ContractStorageReadableKVState`) branches on `getTimestamp()`: an empty optional causes it to read the **latest** row from the database instead of the row valid at the original consensus timestamp. The `consensusTimestamp` field is still present in `ContractDebugParameters` but is never used to pin state when `useHistorical()` is false. [4](#0-3) 

**Root cause / failed assumption:** The code assumes that every `contract_result` row will always have a corresponding `record_file` row reachable via `findByTimestamp`. The query `select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1` returns empty whenever the timestamp exceeds the highest `consensusEnd` in the table — which occurs during ingestion lag, after record-file pruning, or during any DB inconsistency. No error is raised; the fallback is completely silent and the HTTP response is still `200 OK`. [5](#0-4) 

### Impact Explanation
Any caller of `GET /api/v1/contracts/results/{txHash}/opcodes` receives an opcode trace that reflects the **current** contract storage, balances, and bytecode rather than the state at the time the transaction was originally executed. For contracts whose state has changed since the original transaction (e.g., storage slots updated, tokens transferred, contract upgraded), the replayed trace will show different `SLOAD` values, different branch outcomes, and potentially a different execution path than what actually occurred. This directly enables fabrication or distortion of forensic/audit evidence about historical contract execution without any fund theft.

### Likelihood Explanation
The precondition — a `contract_result` row existing while its `record_file` is absent — is reachable by any unprivileged user who:
1. Submits or observes a contract transaction during a period of ingestion lag (the importer writes `contract_result` before the corresponding `record_file` is committed), or
2. Queries a transaction whose record file has been pruned from the mirror node's database (a common operational practice for older data).

No special credentials, admin access, or on-chain privileges are required. The attacker only needs a valid transaction hash, which is publicly observable on-chain. The condition is repeatable and predictable during any ingestion delay window.

### Recommendation
Replace the silent `.orElse(BlockType.LATEST)` with an explicit error:

```java
final var blockType = recordFileService
        .findByTimestamp(consensusTimestamp)
        .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
        .orElseThrow(() -> new EntityNotFoundException(
                "Record file not found for timestamp: " + consensusTimestamp));
```

This aligns with the existing pattern used for `contractResult` on line 156 and ensures the API returns `404` rather than silently replaying against the wrong state. [6](#0-5) 

### Proof of Concept
1. Identify any contract transaction hash `H` whose `consensusTimestamp` `T` is present in `contract_result` but whose record file has been pruned **or** where the mirror node is currently lagging (i.e., `max(consensusEnd)` in `record_file` < `T`).
2. Send: `GET /api/v1/contracts/results/{H}/opcodes` with `Accept-Encoding: gzip`.
3. Observe: HTTP `200 OK` is returned. The `blockType` inside `ContractDebugParameters` is `LATEST`; `ContractCallContext.useHistorical()` returns `false`; all state reads use current DB rows.
4. Compare the returned opcode trace (specifically `SLOAD` values and branch outcomes) against the original execution recorded in the contract's sidecar data — they will differ for any contract whose storage has changed since timestamp `T`.
5. The response contains no indication that the trace is based on the wrong state.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L154-161)
```java
        final var contractResult = contractResultRepository
                .findById(consensusTimestamp)
                .orElseThrow(() -> new EntityNotFoundException("Contract result not found: " + consensusTimestamp));

        final var blockType = recordFileService
                .findByTimestamp(consensusTimestamp)
                .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
                .orElse(BlockType.LATEST);
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L103-105)
```java
    public boolean useHistorical() {
        return callServiceParameters != null && callServiceParameters.getBlock() != BlockType.LATEST;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L111-116)
```java
    public Optional<Long> getTimestamp() {
        if (useHistorical()) {
            return getTimestampOrDefaultFromRecordFile();
        }
        return Optional.empty();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L48-49)
```java
    @Query("select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1")
    Optional<RecordFile> findByTimestamp(long timestamp);
```
