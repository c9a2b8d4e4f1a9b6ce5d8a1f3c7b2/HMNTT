All referenced code has been verified in the repository. Here is the audit result:

---

Audit Report

## Title
Negative Cache Poisoning via `Optional.empty()` in `findByIndex` Allows Unprivileged Users to Hide Valid Blocks for 10 Minutes

## Summary
`RecordFileRepository.findByIndex()` is annotated with `@Cacheable(unless = "#result == null")`. Because the method returns `Optional<RecordFile>`, a miss returns `Optional.empty()` — a non-null Java object — causing the `unless` guard to evaluate to `false` and the empty `Optional` to be stored in the `CACHE_MANAGER_RECORD_FILE_INDEX` Caffeine cache. Any caller who queries a not-yet-indexed block number causes that block to appear missing for the full 10-minute TTL, even after the block is written to the database.

## Finding Description
**Exact code path:**

`RecordFileServiceImpl.findByBlockType()` delegates all numeric block lookups to `recordFileRepository.findByIndex(block.number())`: [1](#0-0) 

`findByIndex` is annotated:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
Optional<RecordFile> findByIndex(long index);
``` [2](#0-1) 

**Root cause:** Spring's `@Cacheable` `unless` expression is evaluated against the method's actual return value. The method returns `Optional<RecordFile>`. When the block does not exist, the repository returns `Optional.empty()` — a non-null Java object. The guard `#result == null` is therefore `false`, and `Optional.empty()` is written into the Caffeine cache under the key equal to the queried block index.

**Cache TTL:** `expireAfterWrite(10, TimeUnit.MINUTES)` with `maximumSize(10000)`: [3](#0-2) 

**Why `@CachePut` on `findByTimestamp` does not rescue this:** `findByTimestamp(long timestamp)` carries a `@CachePut` targeting `CACHE_MANAGER_RECORD_FILE_INDEX`, but Spring uses the method parameter as the default cache key — meaning it stores the result under key = `timestamp` (a nanosecond consensus timestamp), not under key = block `index`. A subsequent `findByIndex(N)` call will always hit the stale `Optional.empty()` entry and never reach the database. [4](#0-3) 

## Impact Explanation
Every API surface that calls `findByBlockType` with a numeric block — including `eth_getBlockByNumber`, `eth_getTransactionByBlockNumberAndIndex`, and the `BLOCKHASH` EVM opcode handler (`MirrorBlockHashOperation.getBlockHash()`) — will return a "block not found" response for up to 10 minutes after the block is actually indexed. [5](#0-4) 

Concrete consequences:
- `eth_getBlockByNumber` returns null for a real block.
- `BLOCKHASH` returns `Hash.ZERO` for a real block, breaking smart-contract calls that depend on recent block hashes.
- The cache holds up to 10,000 entries, so an attacker can pre-poison a large range of future block numbers in a single burst.

## Likelihood Explanation
The web3 JSON-RPC endpoint is publicly accessible with no authentication. An attacker needs only to issue `eth_getBlockByNumber` (or any equivalent call) for a block number that is about to be, or has just been, indexed. Because Hedera produces blocks at a predictable rate, an attacker can trivially predict the next block number and fire the poisoning request before the mirror node finishes indexing it. The attack is repeatable every ~10 minutes (one TTL cycle) with no rate-limiting specific to this path.

## Recommendation
Change the `unless` condition on `findByIndex` to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
    unless = "#result == null || !#result.isPresent()")
Optional<RecordFile> findByIndex(long index);
```

Apply the same fix to `findEarliest()` and the `@Cacheable` inside `findByTimestamp()`'s `@Caching` block, which share the same pattern and are equally affected. [6](#0-5) 

## Proof of Concept
1. Start the mirror node web3 service with a clean database.
2. Send `eth_getBlockByNumber` with a block number `N` that does not yet exist (e.g., the next expected block). The node returns `null` and stores `Optional.empty()` in `CACHE_MANAGER_RECORD_FILE_INDEX` under key `N`.
3. Allow the importer to index block `N` into the database.
4. Immediately send `eth_getBlockByNumber` again for block `N`. The cache is hit, `Optional.empty()` is returned, and the response is still `null` — even though the block now exists in the database.
5. Repeat step 4 for up to 10 minutes; every call returns `null`.
6. To demonstrate `BLOCKHASH` impact: deploy a contract that calls `BLOCKHASH(N)` after step 3. The opcode returns `Hash.ZERO` instead of the real block hash, as confirmed by `MirrorBlockHashOperation.getBlockHash()` returning `Hash.ZERO` on an empty `Optional`. [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L23-49)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_EARLIEST, unless = "#result == null")
    @Query(value = "select * from record_file order by index asc limit 1", nativeQuery = true)
    Optional<RecordFile> findEarliest();

    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);

    @Query("select r from RecordFile r where r.hash like concat(:hash, '%')")
    Optional<RecordFile> findByHash(String hash);

    @Cacheable(
            cacheNames = CACHE_NAME_RECORD_FILE_LATEST,
            cacheManager = CACHE_MANAGER_RECORD_FILE_LATEST,
            unless = "#result == null")
    @Query(value = "select * from record_file order by consensus_end desc limit 1", nativeQuery = true)
    Optional<RecordFile> findLatest();

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/operations/MirrorBlockHashOperation.java (L73-76)
```java
    private Hash getBlockHash(long blockNumber) {
        final var recordFile = recordFileRepository.findByIndex(blockNumber);
        return recordFile.map(this::getBlockHash).orElse(Hash.ZERO);
    }
```
