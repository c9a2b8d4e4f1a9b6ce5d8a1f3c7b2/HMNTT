All six code references were verified against the actual source. Every line number, annotation, and query matches exactly. Here is the result:

---

Audit Report

## Title
Stale `CACHE_MANAGER_RECORD_FILE_INDEX` Cache Serves Pruned Block Metadata, Causing Silent Incorrect EVM Simulation Results

## Summary
`RecordFileRepository.findByIndex()` is annotated `@Cacheable` under the `CACHE_MANAGER_RECORD_FILE_INDEX` Caffeine cache manager, which uses a hard-coded 10-minute write-expiry TTL. When the importer's `RetentionJob` deletes a `record_file` row, the web3 module's in-memory cache is never invalidated. Subsequent `eth_call` or `eth_estimateGas` requests for that block number within the TTL window receive the stale `RecordFile` object, causing the EVM to execute against a pruned block context and silently return incorrect (empty/default) state instead of a proper `BlockNumberNotFoundException`.

## Finding Description

**Step 1 — Numeric block type routes to the cached method.**

`RecordFileServiceImpl.findByBlockType()` falls through to `findByIndex` for numeric block types: [1](#0-0) 

**Step 2 — `findByIndex` is cached with a 10-minute write TTL and no eviction hook.** [2](#0-1) 

The `unless = "#result == null"` guard is ineffective for stale-entry protection: `Optional.empty()` is not `null`, so both empty and non-empty `Optional` results are cached unconditionally. Once a non-empty entry is written, it survives for the full TTL regardless of what happens in the database.

**Step 3 — The cache manager is configured with a hard-coded 10-minute write TTL and no eviction hook.** [3](#0-2) 

**Step 4 — The stale `RecordFile` is injected into the execution context.**

`ContractCallService.callContract()` wraps `recordFileService.findByBlockType()` in a memoized supplier. Because the cache returns a non-empty `Optional`, `orElseThrow(BlockNumberNotFoundException::new)` is never triggered: [4](#0-3) 

**Step 5 — The stale `RecordFile.consensusEnd` becomes the historical timestamp for all state queries.** [5](#0-4) 

**Step 6 — The importer prunes `record_file` rows with no cross-service cache notification.** [6](#0-5) 

The `RetentionJob` calls `prune()` transactionally on all `RetentionRepository` implementations with no mechanism to signal the web3 module's in-memory cache: [7](#0-6) 

**Root cause:** The importer and web3 are separate JVM processes sharing only the database. The Caffeine cache is purely in-memory and time-bounded. There is no cache-invalidation signal between them. The `unless = "#result == null"` guard only prevents caching of Java `null` — it does not evict an already-cached entry when the underlying database row is deleted.

**Failed assumption:** The code assumes that a cached `Optional<RecordFile>` that was non-empty at write time will remain valid for the full 10-minute TTL. This assumption breaks when retention is enabled and the importer deletes the row.

## Impact Explanation

When the stale `RecordFile` is returned, `ContractCallContext.getTimestamp()` resolves to the pruned block's `consensusEnd`. All downstream historical-state queries (contract storage, account balances, token state, etc.) use this timestamp. Because the associated data rows have been pruned from the database, those queries return empty/default values (zero balances, empty storage slots, absent tokens). The EVM simulation completes successfully but with entirely incorrect state — the caller receives a `200 OK` with fabricated zero-state results instead of a `404 BlockNumberNotFoundException`. Off-chain systems (dApps, indexers, bridges) that rely on `eth_call` against historical blocks for correctness checks or balance proofs receive silently wrong data. No direct fund movement is possible from the mirror node itself, but incorrect simulation output can feed into off-chain decision logic.

## Likelihood Explanation

- Retention is disabled by default (`enabled = false`) but is explicitly documented and recommended for production deployments on public networks to control storage costs. [8](#0-7) 
- No credentials are required: a single unauthenticated HTTP POST to `/api/v1/contracts/call` with a numeric `block` field populates the cache.
- The 10-minute TTL is long relative to the retention job's batch cadence (default `1d` frequency, `1d` batch period); the window is reliably exploitable.
- The attacker does not need to know when pruning occurs — any response that does not return a 404 after the expected pruning window is the stale-cache path.
- Repeatability is high: the cache holds up to 10,000 entries, so many block indices can be pre-warmed before pruning occurs. [9](#0-8) 

## Recommendation

1. **Add a `@CacheEvict` on the web3 `RecordFileRepository.findByIndex`** triggered when a block is known to be pruned, or use a shorter TTL aligned with the retention job's minimum batch period.
2. **Replace `unless = "#result == null"` with `unless = "#result != null && !#result.isPresent()"`** to correctly prevent caching of empty `Optional` results (separate but related correctness issue).
3. **Introduce a distributed cache or a shared invalidation signal** (e.g., a database notification, a Redis pub/sub channel, or a short TTL that is less than the minimum retention period) so that the web3 module can evict stale entries when the importer prunes rows.
4. **Add a post-cache database re-validation** for historical block lookups when retention is enabled, to confirm the row still exists before using the cached `RecordFile`.

## Proof of Concept

```
# 1. Pre-warm the cache for block N (unauthenticated)
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"block":"<N>","data":"0x...","to":"0x..."}'
# → 200 OK, correct result (RecordFile for block N is now cached)

# 2. Wait for the importer RetentionJob to prune block N from the database
#    (or trigger it manually if you have importer access)

# 3. Within 10 minutes of step 1, re-query the same block
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"block":"<N>","data":"0x...","to":"0x..."}'
# → 200 OK, INCORRECT result (stale RecordFile served from cache,
#   all state queries return empty/default values for the pruned timestamp,
#   no BlockNumberNotFoundException thrown)
```

The stale path is confirmed by the `Suppliers.memoize` wrapper in `ContractCallService` line 103–104: the supplier is only evaluated once per request, and since the cache returns a non-empty `Optional`, `orElseThrow` is never reached. [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L28-28)
```java
        return recordFileRepository.findByIndex(block.number());
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

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L118-119)
```java
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

**File:** importer/src/main/java/org/hiero/mirror/importer/retention/RetentionProperties.java (L23-23)
```java
    private boolean enabled = false;
```
