### Title
Stale `CACHE_MANAGER_RECORD_FILE_INDEX` Cache Serves Pruned Block Metadata, Causing Silent Incorrect EVM Simulation Results

### Summary
`RecordFileRepository.findByIndex()` is annotated `@Cacheable` with a 10-minute write-expiry TTL under `CACHE_MANAGER_RECORD_FILE_INDEX`. When the importer's `RetentionJob` prunes a `record_file` row from the database, the web3 module's in-memory Caffeine cache is never invalidated. Any subsequent `eth_call` or `eth_estimateGas` request for that block number within the TTL window receives the stale `RecordFile` object, causing the EVM to execute against a pruned block context and silently return incorrect (empty/default) state instead of a proper "block not found" error.

### Finding Description

**Exact code path:**

1. `RecordFileServiceImpl.java` line 28 — numeric block type falls through to:
   ```java
   return recordFileRepository.findByIndex(block.number());
   ```

2. `RecordFileRepository.java` lines 27–29 — the method is annotated:
   ```java
   @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
   @Query("select r from RecordFile r where r.index = ?1")
   Optional<RecordFile> findByIndex(long index);
   ```

3. `EvmConfiguration.java` lines 153–164 — the cache manager is configured with a hard-coded 10-minute write TTL and no eviction hook:
   ```java
   Caffeine.newBuilder()
       .expireAfterWrite(10, TimeUnit.MINUTES)
       .maximumSize(10000)
   ```

4. `ContractCallService.java` lines 103–104 — the stale `RecordFile` is injected into the execution context:
   ```java
   ctx.setBlockSupplier(Suppliers.memoize(() ->
       recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
   ```

5. `ContractCallContext.java` lines 118–119 — the stale `RecordFile.consensusEnd` is used as the historical timestamp for all state queries:
   ```java
   return timestamp.or(() -> Optional.ofNullable(getRecordFile()).map(RecordFile::getConsensusEnd));
   ```

6. In the importer module, `RecordFileRepository.java` line 46 prunes rows with no cross-service cache notification:
   ```java
   @Query("delete from RecordFile where consensusEnd <= ?1")
   int prune(long consensusTimestamp);
   ```

**Root cause:** The `unless = "#result == null"` guard only prevents caching of empty `Optional` results at write time. It does not evict an already-cached entry when the underlying database row is deleted by the importer's `RetentionJob`. The importer and web3 are separate services sharing only the database; there is no cache-invalidation signal between them. The Caffeine cache is purely in-memory and time-bounded, so a cached `RecordFile` for a pruned block survives for up to 10 minutes post-deletion.

**Failed assumption:** The code assumes that a cached `Optional<RecordFile>` that was non-empty at write time will remain valid for the full TTL. This assumption breaks when retention is enabled and the importer deletes the row.

### Impact Explanation

When the stale `RecordFile` is returned, `ContractCallContext.getTimestamp()` resolves to the pruned block's `consensusEnd`. All downstream historical-state queries (contract storage, account balances, token state, etc.) use this timestamp. Because the associated data rows have been pruned from the database, those queries return empty/default values (zero balances, empty storage slots, absent tokens). The EVM simulation completes successfully but with entirely incorrect state — the caller receives a `200 OK` with fabricated zero-state results instead of a `404 BlockNumberNotFoundException`. Off-chain systems (dApps, indexers, bridges) that rely on `eth_call` against historical blocks for correctness checks or balance proofs receive silently wrong data. No direct fund movement is possible from the mirror node itself, but incorrect simulation output can feed into off-chain decision logic.

### Likelihood Explanation

- Retention is disabled by default but is explicitly documented and recommended for production deployments on public networks to control storage costs.
- The attacker needs no credentials: a single unauthenticated HTTP POST to `/api/v1/contracts/call` with a numeric `block` field populates the cache.
- The 10-minute TTL is long relative to the retention job's batch cadence; the window is reliably exploitable.
- The attacker does not need to know when pruning occurs — they simply re-query the same block number repeatedly; any response that does not return a 404 after the expected pruning window is the stale-cache path.
- Repeatability is high: the cache holds up to 10,000 entries, so an attacker can pre-warm many block indices before pruning occurs.

### Recommendation

1. **Add a `@CacheEvict` in the web3 layer** triggered when a block is known to be absent: if `findByIndex` is called and the DB returns empty but the cache holds a value, evict it. Alternatively, change `unless` to also evict on subsequent misses.
2. **Reduce the TTL** for `CACHE_MANAGER_RECORD_FILE_INDEX` to a value shorter than the minimum retention batch period, or make it configurable alongside the retention period.
3. **Cross-service invalidation**: publish a cache-invalidation event (e.g., via the shared database or a message bus) from the importer's `RetentionJob` after each `prune()` call, consumed by the web3 module to evict affected index cache entries.
4. **Validate liveness at use time**: in `ContractCallService.callContract()`, after resolving the `RecordFile` from the supplier, perform a lightweight DB existence check (e.g., `findByIndex` bypassing cache) before proceeding with EVM execution.

### Proof of Concept

**Preconditions:** Mirror node running with `hiero.mirror.importer.retention.enabled=true` and a short retention period so that older blocks are pruned.

1. **Populate the cache** — send an `eth_call` for a specific historical block number (e.g., block 500):
   ```http
   POST /api/v1/contracts/call
   {"block": "0x1F4", "to": "<contract>", "data": "<calldata>"}
   ```
   The response is `200 OK` with correct historical state. `findByIndex(500)` result is now cached for 10 minutes.

2. **Trigger pruning** — wait for or manually trigger the importer `RetentionJob`. Block 500's `record_file` row is deleted via `delete from RecordFile where consensusEnd <= ?1`.

3. **Re-query within TTL** — within 10 minutes of step 1, repeat the same `eth_call`:
   ```http
   POST /api/v1/contracts/call
   {"block": "0x1F4", "to": "<contract>", "data": "<calldata>"}
   ```

4. **Observe incorrect result** — the response is `200 OK` (not `404`). The EVM executed using the stale `RecordFile.consensusEnd` as the historical timestamp. All contract state queries returned empty/default values because the associated data was pruned. The caller receives fabricated zero-state output instead of a block-not-found error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractCallService.java (L103-104)
```java
        ctx.setBlockSupplier(Suppliers.memoize(() ->
                recordFileService.findByBlockType(params.getBlock()).orElseThrow(BlockNumberNotFoundException::new)));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L111-119)
```java
    public Optional<Long> getTimestamp() {
        if (useHistorical()) {
            return getTimestampOrDefaultFromRecordFile();
        }
        return Optional.empty();
    }

    private Optional<Long> getTimestampOrDefaultFromRecordFile() {
        return timestamp.or(() -> Optional.ofNullable(getRecordFile()).map(RecordFile::getConsensusEnd));
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/RecordFileRepository.java (L44-47)
```java
    @Modifying
    @Override
    @Query("delete from RecordFile where consensusEnd <= ?1")
    int prune(long consensusTimestamp);
```
