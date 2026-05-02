All code references have been verified against the actual repository. Here is my determination:

---

## Audit Report

## Title
Stale `CACHE_MANAGER_RECORD_FILE_INDEX` Cache Serves Pruned Block Metadata, Bypassing `BlockNumberNotFoundException` on Historical EVM Calls

## Summary
`RecordFileRepository.findByIndex()` in the web3 module caches `RecordFile` objects with a hard 10-minute write-expiry TTL. The importer's `RetentionJob` deletes `record_file` rows directly in the database with no corresponding cache eviction in the web3 module. Any caller who populated the cache before pruning will receive the stale `RecordFile` for up to 10 minutes, causing `ContractCallService` to silently execute the EVM against a deleted block context instead of throwing `BlockNumberNotFoundException`.

## Finding Description

**Verified code path:**

`RecordFileServiceImpl.findByBlockType()` at line 28 delegates numeric block lookups to `recordFileRepository.findByIndex(block.number())`. [1](#0-0) 

`findByIndex` is annotated `@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")`. Spring Cache unwraps `Optional<RecordFile>` before storage: a present `Optional` stores the raw `RecordFile`; an empty `Optional` is unwrapped to null and skipped by the `unless` guard. A successful lookup therefore stores the `RecordFile` object in the Caffeine cache. [2](#0-1) 

The cache manager `CACHE_MANAGER_RECORD_FILE_INDEX` is configured with `expireAfterWrite(10, TimeUnit.MINUTES)` and no eviction hook. [3](#0-2) 

The importer's `RetentionJob` calls `repository.prune(endTimestamp)` for each `RetentionRepository`, which for `RecordFileRepository` issues `DELETE FROM RecordFile WHERE consensusEnd <= ?1` directly against the database. [4](#0-3) [5](#0-4) 

A search across the entire codebase confirms there is no `@CacheEvict` anywhere in the pruning path. The only `@CacheEvict` usages are in `AddressBookServiceImpl` (importer) and a test file — neither touches `CACHE_MANAGER_RECORD_FILE_INDEX`.

`ContractCallService.callContract()` sets the block supplier as:
```java
recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)
``` [6](#0-5) 

If the cache returns a stale `Optional.of(recordFile)`, `orElseThrow` does not fire. The EVM proceeds using the stale `RecordFile.consensusEnd` as the historical timestamp for all state queries via `ContractCallContext.getTimestamp()`. [7](#0-6) 

**Root cause / failed assumption:** The cache design assumes `record_file` rows are immutable append-only data. This holds when retention is disabled (the default), but breaks when `hiero.mirror.importer.retention.enabled=true` is set — a documented, supported production configuration. [8](#0-7) 

## Impact Explanation

When the stale `RecordFile` is used as the historical block context, all EVM state reads are performed at the pruned block's `consensusEnd` timestamp. The `record_file` row for that block no longer exists in the database, so any subsequent DB lookup keyed on that timestamp (e.g., `findByTimestamp`) will return empty.

**Important correction to the submitted report's impact claim:** The retention documentation explicitly states: *"Only data associated with balance or transaction data is deleted. Cumulative entity information like accounts, contracts, etc. are not deleted."* [9](#0-8) 

Therefore, the claim that "contracts do not exist" and "accounts have zero balance" is overstated. Entity data (accounts, contracts, bytecode, storage current state) is NOT pruned. The actual impact is narrower: historical balance queries and transaction-linked data at the pruned timestamp may return empty/incorrect results, while the system silently proceeds instead of returning a proper `BlockNumberNotFoundException` / "Unknown block number" error. Off-chain systems relying on `eth_call` or `eth_estimateGas` against those specific historical blocks receive incorrect results without any error signal. Severity is Low-to-Medium: no on-chain state changes are possible through the read-only mirror node, and entity data integrity is preserved.

## Likelihood Explanation

Preconditions:
1. Operator has enabled retention (`hiero.mirror.importer.retention.enabled=true`) — disabled by default but a documented cost-saving production practice.
2. Any caller has queried the target block number at least once before it was pruned, populating the `CACHE_MANAGER_RECORD_FILE_INDEX` cache.
3. The same block number is re-queried within the 10-minute TTL window after pruning.

Steps 2 and 3 require no privilege. Any public `eth_call` or `eth_estimateGas` request with a numeric `block` parameter satisfies them. The retention job runs on a configurable schedule (default: daily), making the pruning window predictable. Repeatability is high: every pruning cycle creates a new 10-minute window for every previously-cached pruned block index.

## Recommendation

1. **Add `@CacheEvict` to the pruning path in the web3 module.** Since the importer and web3 are separate processes, a direct `@CacheEvict` on the importer's `RecordFileRepository.prune()` cannot reach the web3 module's cache. The correct fix is to reduce the TTL of `CACHE_MANAGER_RECORD_FILE_INDEX` to a value shorter than the minimum retention period, or to use `expireAfterAccess` instead of `expireAfterWrite` so that infrequently-accessed pruned entries expire naturally.

2. **Add a post-cache DB existence check.** After retrieving a `RecordFile` from `findByIndex`, verify the row still exists in the database before using it as a historical context. If absent, evict the stale entry and throw `BlockNumberNotFoundException`.

3. **Document the cache-retention interaction.** The assumption that `record_file` rows are immutable should be explicitly noted in the cache configuration, with a comment that the TTL must be shorter than the minimum retention batch period.

## Proof of Concept

```
1. Enable retention: hiero.mirror.importer.retention.enabled=true
   (retention.period set to prune blocks older than N days)

2. Populate cache — send any eth_call with a numeric block parameter
   targeting block index B (which is within the retention window):
     POST /api/v1/contracts/call
     {"block": "<B>", "data": "0x...", "to": "0x..."}
   → RecordFile for index B is now stored in CACHE_MANAGER_RECORD_FILE_INDEX
     with a 10-minute write-expiry TTL.

3. RetentionJob runs and deletes the record_file row for block B from the DB.
   No cache eviction occurs in the web3 process.

4. Within 10 minutes of step 2, re-send the same eth_call:
     POST /api/v1/contracts/call
     {"block": "<B>", "data": "0x...", "to": "0x..."}

5. Observed: RecordFileRepository.findByIndex(B) returns the stale
   Optional.of(recordFile) from cache. orElseThrow(BlockNumberNotFoundException::new)
   does NOT fire. The EVM executes using recordFile.consensusEnd as the
   historical timestamp. Historical balance/transaction queries at that
   timestamp return empty results. The caller receives a (possibly empty/zero)
   EVM result instead of "Unknown block number".

Expected: BlockNumberNotFoundException → HTTP 400 "Unknown block number".
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-29)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
        } else if (block.isHash()) {
            return recordFileRepository.findByHash(block.name());
        }

        return recordFileRepository.findByIndex(block.number());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L153-164)
```java
    @Bean(CACHE_MANAGER_RECORD_FILE_INDEX)
    @Primary
    CacheManager cacheManagerRecordFileIndex() {
        final var caffeine = Caffeine.newBuilder()
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .maximumSize(10000)
                .recordStats();
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCaffeine(caffeine);
        return caffeineCacheManager;
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/retention/RetentionJob.java (L73-80)
```java
        transactionOperations.executeWithoutResult(t -> retentionRepositories.forEach(repository -> {
            String table = getTableName(repository);

            if (retentionProperties.shouldPrune(table)) {
                long count = repository.prune(endTimestamp);
                counters.merge(table, count, Long::sum);
            }
        }));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/RecordFileRepository.java (L44-47)
```java
    @Modifying
    @Override
    @Query("delete from RecordFile where consensusEnd <= ?1")
    int prune(long consensusTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L100-107)
```java
    protected final EvmTransactionResult callContract(CallServiceParameters params, ContractCallContext ctx)
            throws MirrorEvmTransactionException {
        ctx.setCallServiceParameters(params);
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));

        return doProcessCall(params, params.getGas(), false);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L111-120)
```java
    public Optional<Long> getTimestamp() {
        if (useHistorical()) {
            return getTimestampOrDefaultFromRecordFile();
        }
        return Optional.empty();
    }

    private Optional<Long> getTimestampOrDefaultFromRecordFile() {
        return timestamp.or(() -> Optional.ofNullable(getRecordFile()).map(RecordFile::getConsensusEnd));
    }
```

**File:** docs/database/README.md (L94-106)
```markdown
On public networks, mirror nodes can generate tens of gigabytes worth of data every day and this rate is only projected
to increase. Mirror nodes support an optional data retention period that is disabled by default. When enabled, the
retention job purges historical data beyond a configured time period. By reducing the overall amount of data in the
database it will reduce operational costs and improve read/write performance. Only data associated with balance
or transaction data is deleted. Cumulative entity information like accounts, contracts, etc. are not deleted.

To enable retention, set the `hiero.mirror.importer.retention.enabled=true` property on the importer. A job will run
every `hiero.mirror.importer.retention.frequency` with a default of one day to prune older data. To control how far
back to remove data set the `hiero.mirror.importer.retention.period` appropriately. Keep in mind this retention period
is relative to the timestamp of the last transaction in the database and not to the current wall-clock time. Data is
deleted atomically one or more blocks at a time starting from the earliest block and increasing, so data should be
consistent even when querying the earliest data. There are also `hiero.mirror.importer.retention.exclude/include`
properties that can be used to filter which tables are included or excluded from retention, defaulting to include all.
```
