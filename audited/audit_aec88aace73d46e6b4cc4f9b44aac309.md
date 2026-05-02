### Title
Permanent Cache Poisoning of `recordFileEarliest` via `Optional.empty()` Bypass of `unless` Guard

### Summary
The `findEarliest()` method in `RecordFileRepository` uses `unless = "#result == null"` to prevent caching empty results, but the method returns `Optional<RecordFile>`. When the database has no record files, the return value is `Optional.empty()` — which is **not null** — so the guard is bypassed and the empty result is stored permanently in a no-TTL, single-entry cache. Any unprivileged user who triggers this during the startup window (before the first record file is ingested) causes all subsequent `BlockType.EARLIEST` queries to return empty forever, until the service is restarted.

### Finding Description

**Cache configuration** — `EvmConfiguration.java`, lines 190–197:
```java
@Bean(CACHE_MANAGER_RECORD_FILE_EARLIEST)
CacheManager cacheManagerRecordFileEarliest() {
    final var caffeine = Caffeine.newBuilder().maximumSize(1).recordStats();
    // No expireAfterWrite / expireAfterAccess — entries never expire
    ...
}
``` [1](#0-0) 

**Flawed cache guard** — `RecordFileRepository.java`, line 23:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST,
           unless = "#result == null")
Optional<RecordFile> findEarliest();
``` [2](#0-1) 

Spring's `@Cacheable` `unless` expression evaluates against the actual return value. Since the method signature is `Optional<RecordFile>`, a miss on an empty table returns `Optional.empty()`. `Optional.empty() != null`, so `unless = "#result == null"` evaluates to `false`, and the empty Optional **is written into the cache**.

The cache has `maximumSize(1)` and **no TTL**. Once `Optional.empty()` occupies the single slot, it stays there indefinitely. Every subsequent call to `findEarliest()` hits the cache and returns `Optional.empty()` without ever querying the database again.

**Call path to trigger:**
```
HTTP request (block = "earliest")
  → RecordFileServiceImpl.findByBlockType(BlockType.EARLIEST)   [line 20-21]
  → RecordFileRepository.findEarliest()                          [line 23-25]
  → DB returns empty → Optional.empty() cached permanently
``` [3](#0-2) 

**Contrast with `findLatest()`**: that cache uses `expireAfterWrite(500, TimeUnit.MILLISECONDS)`, so any poisoned entry self-heals in 500 ms. The `findEarliest()` cache has no such safety valve. [4](#0-3) 

### Impact Explanation
After the cache is poisoned, every call to `eth_getBlockByNumber("earliest", ...)`, `eth_call` with block tag `earliest`, or any other API path that resolves `BlockType.EARLIEST` returns an empty/not-found response for all users. The service must be restarted to recover. This is a targeted, permanent denial-of-service for the earliest-block feature with no economic damage — consistent with the Medium/griefing classification.

### Likelihood Explanation
The exploit requires the attacker to send one HTTP request during the window between service startup and the first record file being ingested into the database. This window is predictable (mirror nodes are publicly observable; restart events are visible via monitoring gaps or version-upgrade announcements). No credentials, special permissions, or on-chain funds are required — a single unauthenticated HTTP request suffices. The attack is repeatable after every service restart.

### Recommendation
Change the `unless` condition to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST,
    unless = "#result == null || !#result.isPresent()"
)
Optional<RecordFile> findEarliest();
```

Additionally, add a short TTL (e.g., `expireAfterWrite(60, TimeUnit.SECONDS)`) to `cacheManagerRecordFileEarliest()` as a defense-in-depth measure, mirroring the pattern used by `cacheManagerRecordFileLatest()`. [5](#0-4) 

### Proof of Concept
1. Start the mirror-node web3 service against an empty (or freshly wiped) `record_file` table.
2. Before any record file is ingested, send:
   ```
   POST /api/v1/contracts/call
   { "blockType": "earliest", "data": "0x", "to": "0x..." }
   ```
   or any JSON-RPC call: `eth_getBlockByNumber("earliest", false)`
3. Observe the response is empty/not-found (expected at this point).
4. Now ingest one or more record files into the database normally.
5. Repeat the same request from step 2.
6. **Expected (correct) behavior**: returns the genesis record file.
7. **Actual behavior**: still returns empty/not-found — the `Optional.empty()` from step 2 is permanently cached and the database is never queried again.
8. Restart the service; the correct genesis block is now returned, confirming the cache was the cause.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L178-188)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-22)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
```
