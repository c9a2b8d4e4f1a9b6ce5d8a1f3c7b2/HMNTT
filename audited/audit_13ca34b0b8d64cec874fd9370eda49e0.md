### Title
Silent `BlockType.LATEST` Fallback in `OpcodeServiceImpl.buildCallServiceParameters()` Causes Historical Opcode Trace Execution Against Current Chain State

### Summary
When `recordFileService.findByTimestamp()` returns empty for a valid historical transaction, `OpcodeServiceImpl.buildCallServiceParameters()` silently falls back to `BlockType.LATEST` instead of failing. This causes `ContractCallContext.useHistorical()` to return `false`, which in turn causes `getTimestamp()` to return `Optional.empty()`, making every downstream EVM state read (accounts, storage, bytecode, tokens) execute against the current chain state rather than the historical state at the time of the original transaction. The resulting opcode trace is falsified.

### Finding Description

**Exact code path:**

`OpcodeServiceImpl.java` lines 158–161:
```java
final var blockType = recordFileService
        .findByTimestamp(consensusTimestamp)
        .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
        .orElse(BlockType.LATEST);   // ← silent fallback
``` [1](#0-0) 

`ContractCallContext.java` lines 103–105 — the gating predicate:
```java
public boolean useHistorical() {
    return callServiceParameters != null && callServiceParameters.getBlock() != BlockType.LATEST;
}
``` [2](#0-1) 

`ContractCallContext.java` lines 111–116 — timestamp propagation:
```java
public Optional<Long> getTimestamp() {
    if (useHistorical()) {
        return getTimestampOrDefaultFromRecordFile();
    }
    return Optional.empty();   // ← returns empty when block == LATEST
}
``` [3](#0-2) 

`ContractDebugService.java` line 51 sets the timestamp on the context, but this is discarded because `getTimestamp()` short-circuits when `useHistorical()` is false: [4](#0-3) 

Every readable KV state (`AccountReadableKVState`, `TokenReadableKVState`, `ContractStorageReadableKVState`, etc.) calls `ctx.getTimestamp()` to decide whether to query historical or current DB rows. With an empty timestamp they all read current state.

**Root cause / failed assumption:** The code assumes `findByTimestamp` will always find a record file for any valid `consensusTimestamp` that has a corresponding `contract_result` row. This assumption breaks when the retention system prunes the `record_file` table independently of other tables.

**How `findByTimestamp` returns empty:**

The `RecordFileRepository` query is:
```sql
select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1
``` [5](#0-4) 

This returns empty when no record file with `consensusEnd >= consensusTimestamp` exists — i.e., when all record files have been pruned up to or past that timestamp.

**The retention system makes this a realistic operational condition.** The `RetentionJob` prunes tables independently and supports per-table include/exclude configuration: [6](#0-5) 

The `contract_result` table implements `RetentionRepository` with its own prune boundary: [7](#0-6) 

Configuration `hiero.mirror.importer.retention.include=[record_file]` (or `exclude=[contract_result,transaction,contract_transaction_hash]`) causes record files to be pruned while contract results and transaction hashes remain. The documentation explicitly supports this: [8](#0-7) 

**Why existing checks are insufficient:**

- There is no guard in `buildCallServiceParameters` that throws when `findByTimestamp` returns empty for a transaction that has a `contract_result`.
- `ContractDebugService.processOpcodeCall()` sets `ctx.setTimestamp(...)` but this is silently ignored because `useHistorical()` is false.
- No validation in `ContractCallService.callContract()` checks that a debug/opcode call must be historical.

### Impact Explanation

An attacker (or any user) who requests an opcode trace for a transaction whose record file has been pruned receives a trace that:
- Executes against the **current** contract bytecode (if the contract was upgraded after the original transaction)
- Reads **current** storage slots, token balances, and account states
- May follow entirely different execution paths than the original transaction
- Returns a `200 OK` response with no error indication

This falsifies the forensic record of what a contract did at a specific point in time. For contracts involved in disputes, audits, or incident response, this produces misleading evidence. The severity is **medium-high**: the data integrity of the opcode tracing endpoint is broken for any deployment with asymmetric retention policies.

### Likelihood Explanation

- The retention feature is documented and production-ready (default period 90 days).
- Operators commonly prune `record_file` to reduce storage while retaining contract data for compliance.
- Transaction hashes are publicly visible via the mirror node REST API — no privileged access is needed to obtain a valid hash for an old transaction.
- The trigger is a single unauthenticated HTTP request to the opcode trace endpoint.
- The condition is persistent (not a race), so it is reliably reproducible for every affected transaction.

### Recommendation

Replace the silent `.orElse(BlockType.LATEST)` fallback with an explicit error:

```java
// In OpcodeServiceImpl.buildCallServiceParameters (lines 158-161)
final var blockType = recordFileService
        .findByTimestamp(consensusTimestamp)
        .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
        .orElseThrow(() -> new EntityNotFoundException(
                "Record file not found for timestamp: " + consensusTimestamp));
```

Additionally, add a precondition guard in `ContractDebugService.processOpcodeCall()` or `ContractCallService.callContract()` that asserts `useHistorical()` is `true` when a `consensusTimestamp` is present in the parameters, so that any future regression is caught at the call boundary rather than silently degrading to current-state execution.

### Proof of Concept

**Preconditions:**
1. Mirror node with retention enabled: `hiero.mirror.importer.retention.enabled=true`, `hiero.mirror.importer.retention.include=record_file` (prune only record files, keep contract data).
2. At least one historical contract transaction exists in `contract_result` and `contract_transaction_hash` whose record file has been pruned.

**Steps:**
1. Query the mirror node REST API for any historical contract transaction hash: `GET /api/v1/contracts/results?timestamp=lt:<pruned_boundary>` — returns hashes of transactions whose record files no longer exist.
2. Call the opcode trace endpoint with that hash: `GET /api/v1/contracts/results/{txHash}/opcodes`
3. `OpcodeServiceImpl.buildCallServiceParameters()` resolves `consensusTimestamp` from `contract_transaction_hash`, finds `contract_result` (still present), calls `recordFileService.findByTimestamp(consensusTimestamp)` → returns `Optional.empty()` → `blockType = BlockType.LATEST`.
4. `ContractCallContext.useHistorical()` returns `false`; `getTimestamp()` returns `Optional.empty()`.
5. EVM executes against current state; opcode trace reflects current bytecode and storage, not the historical values at `consensusTimestamp`.
6. Response is `200 OK` with a plausible-looking but incorrect opcode trace — no error is surfaced to the caller.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/OpcodeServiceImpl.java (L158-161)
```java
        final var blockType = recordFileService
                .findByTimestamp(consensusTimestamp)
                .map(recordFile -> BlockType.of(recordFile.getIndex().toString()))
                .orElse(BlockType.LATEST);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractDebugService.java (L51-51)
```java
        ctx.setTimestamp(Optional.of(params.getConsensusTimestamp() - 1));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L48-49)
```java
    @Query("select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1")
    Optional<RecordFile> findByTimestamp(long timestamp);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/ContractResultRepository.java (L10-15)
```java
public interface ContractResultRepository extends CrudRepository<ContractResult, Long>, RetentionRepository {

    @Modifying
    @Override
    @Query("delete from ContractResult where consensusTimestamp <= ?1")
    int prune(long consensusTimestamp);
```

**File:** docs/configuration.md (L230-235)
```markdown
| `hiero.mirror.importer.retention.batchPeriod`                                   | 1d                                                   | How often to commit deletions when pruning.                                                                                                                                                                                                                        |
| `hiero.mirror.importer.retention.enabled`                                       | false                                                | Whether to data retention should be enabled to purge older data.                                                                                                                                                                                                   |
| `hiero.mirror.importer.retention.exclude`                                       | []                                                   | Which tables to exclude when pruning data. By default it is empty to indicate no tables will be excluded from retention.                                                                                                                                           |
| `hiero.mirror.importer.retention.frequency`                                     | 1d                                                   | How often to run the retention job to purge older data. If it is already running from a previous period, skip execution. If not specified, millisecond is implied as the unit.                                                                                     |
| `hiero.mirror.importer.retention.include`                                       | []                                                   | Which tables to include when pruning data. By default it is empty to indicate all tables that can be pruned will be.                                                                                                                                               |
| `hiero.mirror.importer.retention.period`                                        | 90d                                                  | How far in the past to remove data. This value is relative to the timestamp of the last transaction in the database and not to the current time.                                                                                                                   |
```
