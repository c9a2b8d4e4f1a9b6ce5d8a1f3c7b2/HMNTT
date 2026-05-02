### Title
Indefinite Stale `gasUsed`/`logsBloom` Served via `expireAfterAccess` Cache with No Invalidation on DB Update

### Summary
`RecordFileRepository.findByTimestamp()` caches results in `CACHE_MANAGER_RECORD_FILE_TIMESTAMP` using Caffeine's `expireAfterAccess(10, TimeUnit.MINUTES)` policy. Because expiry resets on every read, an unprivileged user who repeatedly queries the same block timestamp can keep a stale cache entry alive indefinitely after the underlying `record_file` row has been updated (e.g., by `BackfillBlockMigration` correcting `gasUsed`/`logsBloom`). No `@CacheEvict` exists anywhere for this cache, so the web3 layer has no mechanism to detect or discard the outdated entry.

### Finding Description

**Cache configuration** — `EvmConfiguration.java` lines 166–176: [1](#0-0) 

`expireAfterAccess` resets the TTL clock on every cache read. A cache entry that is accessed at least once every 10 minutes never expires.

**Cache population with no eviction** — `RecordFileRepository.java` lines 38–46: [2](#0-1) 

`@Cacheable` populates the cache on first miss; `@CachePut` writes to the index cache as a side-effect. There is no `@CacheEvict` on any write path for `CACHE_MANAGER_RECORD_FILE_TIMESTAMP` — confirmed by a full-codebase search returning zero matches for any eviction of this cache.

**DB update path that bypasses the cache** — `BackfillBlockMigration.java` lines 82–108: [3](#0-2) 

`BackfillBlockMigration` (importer service) calls `recordFileRepository.save(recordFile)` to correct `gasUsed` and `logsBloom` for blocks that were initially stored with `gasUsed = -1`. This write goes directly to the DB; the web3 module's Caffeine cache is a separate in-process store and is never notified.

**Exploit flow**:
1. A record file is ingested with `gasUsed = -1` (default before backfill; see `RecordFile.java` line 58). [4](#0-3) 
2. Any client queries the block by timestamp → `findByTimestamp()` misses the cache, hits the DB, and stores `{gasUsed: -1, logsBloom: null}` in `CACHE_MANAGER_RECORD_FILE_TIMESTAMP`.
3. `BackfillBlockMigration` runs (asynchronously, during or after node startup) and writes the correct `gasUsed`/`logsBloom` to the DB.
4. The attacker (no credentials required) sends repeated JSON-RPC calls (e.g., `eth_getBlockByNumber`) for the same block timestamp at intervals shorter than 10 minutes. Each call hits the cache, returns the stale value, and resets the `expireAfterAccess` timer.
5. The cache entry never expires. All consumers — including downstream EVM tooling — receive `gasUsed = -1` and a zeroed `logsBloom` for that block indefinitely.

### Impact Explanation
`gasUsed` at the block level is used by Ethereum-compatible tooling (block explorers, gas estimators, EIP-1559 base-fee calculators) to determine block fullness. Serving `gasUsed = -1` (or a stale pre-migration value) causes these tools to compute incorrect base fees, misreport block utilization, and potentially break applications that rely on `logsBloom` for efficient log filtering. Because the web3 module is the EVM-compatibility layer for the mirror node, the impact propagates to every consumer of the JSON-RPC endpoint.

### Likelihood Explanation
The precondition (a record file with `gasUsed = -1` being cached before `BackfillBlockMigration` completes) is a normal operational state during any mirror node upgrade or initial sync. The attacker requires no authentication, no special knowledge beyond a valid block number, and only needs to issue periodic HTTP requests — well within the capability of any script. The `maximumSize(10000)` limit means up to 10,000 distinct block timestamps can be pinned simultaneously, amplifying the attack surface.

### Recommendation
1. Replace `expireAfterAccess` with `expireAfterWrite` for `CACHE_MANAGER_RECORD_FILE_TIMESTAMP` so that entries expire a fixed time after being written, regardless of read activity.
2. Add a `@CacheEvict` (or `@Caching` with evict) on any repository method that saves/updates a `RecordFile` in the web3 module, or introduce a cross-service cache invalidation signal from the importer.
3. Consider using `expireAfterWrite` with a short TTL (e.g., 1–2 minutes) consistent with the `CACHE_MANAGER_RECORD_FILE_LATEST` pattern (500 ms write TTL) for mutable fields like `gasUsed`.

### Proof of Concept
```
# 1. Identify a block whose record file has gasUsed = -1 (pre-migration state)
#    e.g., block number 1000 with consensusEnd timestamp T

# 2. Prime the cache (first request hits DB, stores stale value)
curl -X POST http://<mirror-node>:8545 \
  -H 'Content-Type: application/json' \
  -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3E8",false],"id":1}'
# Response: "gasUsed": "0x..." (stale -1 or pre-migration value)

# 3. BackfillBlockMigration runs and updates record_file SET gas_used = <correct> WHERE consensus_end = T

# 4. Attacker keeps cache alive (run every ~9 minutes):
while true; do
  curl -s -X POST http://<mirror-node>:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["0x3E8",false],"id":1}' | \
    jq '.result.gasUsed'
  sleep 540
done
# Output: stale gasUsed value returned indefinitely, never refreshed from DB
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L166-176)
```java
    @Bean(CACHE_MANAGER_RECORD_FILE_TIMESTAMP)
    CacheManager cacheManagerRecordFileTimestamp() {
        final var caffeine = Caffeine.newBuilder()
                .expireAfterAccess(10, TimeUnit.MINUTES)
                .maximumSize(10000)
                .recordStats();
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCaffeine(caffeine);
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L38-46)
```java
    @Caching(
            cacheable =
                    @Cacheable(
                            cacheNames = CACHE_NAME,
                            cacheManager = CACHE_MANAGER_RECORD_FILE_TIMESTAMP,
                            unless = "#result == null"),
            put = @CachePut(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX))
    @Query("select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1")
    Optional<RecordFile> findByTimestamp(long timestamp);
```

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/BackfillBlockMigration.java (L82-108)
```java
    protected Optional<Long> migratePartial(Long lastConsensusEnd) {
        return recordFileRepositoryProvider
                .getObject()
                .findLatestMissingGasUsedBefore(lastConsensusEnd)
                .map(recordFile -> {
                    var queryParams = Map.of(
                            "consensusStart",
                            recordFile.getConsensusStart(),
                            "consensusEnd",
                            recordFile.getConsensusEnd());

                    var logsBloomFilter = new LogsBloomFilter();
                    var gasUsedTotal = new AtomicLong(0);
                    getNamedParameterJdbcOperations().query(SELECT_CONTRACT_RESULT, queryParams, rs -> {
                        logsBloomFilter.or(rs.getBytes("bloom"));
                        gasUsedTotal.addAndGet(rs.getLong("gas_used"));
                    });

                    recordFile.setGasUsed(gasUsedTotal.get());
                    recordFile.setLogsBloom(logsBloomFilter.toArrayUnsafe());
                    recordFileRepositoryProvider.getObject().save(recordFile);

                    // set transaction index for the transactions in the record file
                    getNamedParameterJdbcOperations().update(SET_TRANSACTION_INDEX, queryParams);

                    return recordFile.getConsensusEnd();
                });
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/transaction/RecordFile.java (L57-59)
```java
    @Builder.Default
    private long gasUsed = 0L;

```
