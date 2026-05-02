All code references verified. The vulnerability is real and technically sound.

---

Audit Report

## Title
Permanent Cache Poisoning of Earliest Record File via Insufficient `unless` Guard on No-Expiry Cache

## Summary
`cacheManagerRecordFileEarliest()` creates a Caffeine cache with no TTL, and `findEarliest()` uses `unless = "#result == null"` to prevent caching empty results. Because the return type is `Optional<RecordFile>`, an empty database returns `Optional.empty()` — a non-null singleton — so the `unless` guard never fires, the empty result is stored permanently, and all subsequent calls return `Optional.empty()` for the lifetime of the process.

## Finding Description

**Cache bean — no TTL:**

`cacheManagerRecordFileEarliest()` builds a Caffeine cache with only `maximumSize(1)` and no `expireAfterWrite` / `expireAfterAccess`. [1](#0-0) 

Contrast with `cacheManagerRecordFileLatest()`, which has `expireAfterWrite(500, TimeUnit.MILLISECONDS)` as a safety valve, and `cacheManagerRecordFileIndex()` / `cacheManagerRecordFileTimestamp()`, which both use `expireAfterWrite(10, TimeUnit.MINUTES)`. [2](#0-1) 

**Repository method — broken `unless` guard:**

```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
Optional<RecordFile> findEarliest();
``` [3](#0-2) 

**Root cause:** Spring's `@Cacheable` evaluates the `unless` SpEL expression against the actual return value — the `Optional` object itself, not its contents. When the DB has no rows, Spring Data JPA returns `Optional.empty()`. `Optional.empty()` is a non-null singleton, so `#result == null` → `false`, and the empty result is written into the no-expiry cache. Spring's Optional-unwrapping logic then stores `null` internally; on every subsequent call the cache hit returns `null`, which Spring re-wraps as `Optional.empty()`, permanently hiding any data that arrives later.

**Call path to the vulnerable method:**

`eth_getBlockByNumber("earliest", ...)` → `RecordFileServiceImpl.findByBlockType(BlockType.EARLIEST)` → `recordFileRepository.findEarliest()`. [4](#0-3) 

## Impact Explanation
Every downstream consumer that queries for the earliest block — `eth_getBlockByNumber("earliest", ...)`, block-range validation, historical EVM execution anchored to genesis — will permanently receive an empty result for the lifetime of the process. Features depending on the genesis/earliest block will return incorrect error responses or silently produce data gaps for all mirror-node consumers. The only recovery is a full process restart. Severity is **High**: the impact is persistent, affects all users, and requires no privileges to trigger.

## Likelihood Explanation
The precondition — the web3 service being reachable before the first `record_file` row exists — is a normal operational state during initial deployment or after a database wipe. No authentication is required to call `eth_getBlockByNumber`. The attacker needs only network access to the JSON-RPC port. The attack is a single HTTP request and is trivially repeatable across restarts.

## Recommendation
Change the `unless` guard to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST,
    unless = "#result == null || !#result.isPresent()"
)
Optional<RecordFile> findEarliest();
```

Additionally, add a TTL to `cacheManagerRecordFileEarliest()` as a defence-in-depth measure (e.g. `expireAfterWrite(10, TimeUnit.MINUTES)`), consistent with the other record-file caches. [1](#0-0) 

Note: `findByIndex` and `findByTimestamp` carry the same `unless = "#result == null"` pattern, but their caches have 10-minute TTLs that bound the blast radius. [5](#0-4) 

## Proof of Concept
1. Start the mirror-node web3 service against an empty database (no `record_file` rows).
2. Send a single JSON-RPC request:
   ```
   POST /
   {"jsonrpc":"2.0","method":"eth_getBlockByNumber","params":["earliest",false],"id":1}
   ```
3. The DB query `select * from record_file order by index asc limit 1` returns zero rows → Spring Data returns `Optional.empty()`.
4. `unless = "#result == null"` → `Optional.empty() == null` → `false` → Spring caches the empty result in the no-expiry Caffeine cache.
5. Populate the database with record files via the importer.
6. Repeat the same JSON-RPC request — the response still indicates no earliest block, confirming the cache is poisoned.
7. Restart the process; the first request now returns the correct earliest block, confirming the poison is process-lifetime only.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L153-188)
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

    @Bean(CACHE_MANAGER_RECORD_FILE_LATEST)
    CacheManager cacheManagerRecordFileLatest() {
        final var caffeine = Caffeine.newBuilder()
                .expireAfterWrite(500, TimeUnit.MILLISECONDS)
                .maximumSize(1)
                .recordStats();
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_RECORD_FILE_LATEST));
        caffeineCacheManager.setCaffeine(caffeine);
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L190-197)
```java
    @Bean(CACHE_MANAGER_RECORD_FILE_EARLIEST)
    CacheManager cacheManagerRecordFileEarliest() {
        final var caffeine = Caffeine.newBuilder().maximumSize(1).recordStats();
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCaffeine(caffeine);
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L23-25)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
    @Query(value = "select * from record_file order by index asc limit 1", nativeQuery = true)
    Optional<RecordFile> findEarliest();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-22)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
```
