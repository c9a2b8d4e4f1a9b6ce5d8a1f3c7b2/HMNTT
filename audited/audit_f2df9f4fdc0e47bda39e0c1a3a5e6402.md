### Title
Cache Miss DoS via Non-Existent Block Numbers in `findByIndex` — Empty Results Never Cached

### Summary
`RecordFileServiceImpl.findByBlockType()` delegates to `recordFileRepository.findByIndex(block.number())` for any numeric block. The `@Cacheable` annotation on `findByIndex` uses `unless = "#result == null"`, but Spring unwraps `Optional` return values before evaluating SpEL — so `Optional.empty()` becomes `null`, triggering the `unless` condition and preventing the empty result from ever being stored in the cache. An unprivileged attacker can flood the service with requests using unique non-existent block numbers, each forcing a live database query with zero cache benefit.

### Finding Description

**Code path:**

`RecordFileServiceImpl.java` lines 19–27:
```java
public Optional<RecordFile> findByBlockType(BlockType block) {
    if (block == BlockType.EARLIEST) { return recordFileRepository.findEarliest(); }
    else if (block == BlockType.LATEST) { return recordFileRepository.findLatest(); }
    return recordFileRepository.findByIndex(block.number()); // ← hit for any numeric block
}
```

`RecordFileRepository.java` lines 27–29:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
           unless = "#result == null")
Optional<RecordFile> findByIndex(long index);
```

**Root cause:** Spring Framework's `@Cacheable` unwraps `Optional<T>` before evaluating SpEL expressions. When `findByIndex` returns `Optional.empty()` (block index not in `record_file` table), Spring evaluates `#result` as `null` (the unwrapped content), making `unless = "#result == null"` evaluate to `true`, which suppresses caching. The cache manager `CACHE_MANAGER_RECORD_FILE_INDEX` is configured with `maximumSize(10000)` and `expireAfterWrite(10 minutes)` — but this capacity is irrelevant because misses are never stored.

**Failed assumption:** The developer assumed `#result == null` guards against caching absent DB rows, but it also silently prevents caching of `Optional.empty()` — the exact case that needs negative caching to protect the database.

**Exploit flow:**
1. Attacker calls any public JSON-RPC endpoint that resolves a block (e.g., `eth_getBlockByNumber`, `eth_call` with a block parameter).
2. `BlockType.of("0xFFFFFFF1")`, `BlockType.of("0xFFFFFFF2")`, … each produces a distinct numeric `BlockType`.
3. Each request reaches `findByBlockType` → `findByIndex(N)` → cache miss → JPQL query `SELECT r FROM RecordFile r WHERE r.index = ?1` → `Optional.empty()` → not cached.
4. The next request with a different non-existent number repeats identically.
5. With concurrent threads sending unique non-existent block numbers, every single request hits the database.

### Impact Explanation
Every unique non-existent block number generates an uncached database round-trip. The database query (`SELECT … WHERE index = ?1`) is lightweight individually, but under sustained parallel load with unique values the DB connection pool saturates, query latency rises, and legitimate requests are starved. Because the `record_file` table grows only as new blocks are ingested (~1 block every few seconds on Hedera), the attacker has an effectively unbounded space of non-existent indices (any value above the current chain tip). This directly maps to the stated threat: ≥30% increase in DB/node resource consumption without brute-force credential attacks.

### Likelihood Explanation
The JSON-RPC API is public and unauthenticated. No rate limiting is visible in the service or repository layer. `BlockType.of()` accepts both decimal and hex strings, making it trivial to generate millions of unique non-existent block numbers programmatically. A single attacker with a modest HTTP client can sustain thousands of requests per second. The attack is fully repeatable and requires no special knowledge beyond the public API spec.

### Recommendation
Cache negative results explicitly. Replace the `unless` condition to also allow caching of `Optional.empty()`:

```java
// Change from:
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
           unless = "#result == null")

// To (cache both hits and misses; Optional.empty() will be stored):
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX)
```

Alternatively, use `unless = "#result != null && !#result.isPresent()"` only if you intentionally want to exclude empty optionals from a different cache, but for this index cache, negative caching is desirable. Additionally, consider adding rate limiting (e.g., via a `RateLimiter` or API gateway) on block-number-parameterized endpoints to bound the worst-case DB query rate regardless of caching behavior.

### Proof of Concept
```bash
# Send 50,000 requests with unique non-existent block numbers (above current chain tip)
# Each will bypass the cache and hit the DB directly.

BASE=9999999000
for i in $(seq 1 50000); do
  BLOCK=$(printf '0x%x' $((BASE + i)))
  curl -s -X POST http://<mirror-node-web3>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"block\":\"$BLOCK\",\"data\":\"0x\",\"to\":\"0x0000000000000000000000000000000000000001\"}" &
done
wait
# Monitor DB: SELECT count(*), avg(total_time) FROM pg_stat_statements WHERE query LIKE '%record_file%index%';
# Observe: query count and avg latency spike proportionally to request rate.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L19-27)
```java
    public Optional<RecordFile> findByBlockType(BlockType block) {
        if (block == BlockType.EARLIEST) {
            return recordFileRepository.findEarliest();
        } else if (block == BlockType.LATEST) {
            return recordFileRepository.findLatest();
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

**File:** web3/src/main/java/org/hiero/mirror/web3/viewmodel/BlockType.java (L37-55)
```java
    private static BlockType extractNumericBlock(String value) {
        int radix = 10;
        var cleanedValue = value;

        if (value.startsWith(HEX_PREFIX)) {
            radix = 16;
            cleanedValue = Strings.CS.removeStart(value, HEX_PREFIX);
        }

        if (cleanedValue.contains(NEGATIVE_NUMBER_PREFIX)) {
            throw new IllegalArgumentException("Invalid block value: " + value);
        }

        try {
            long blockNumber = Long.parseLong(cleanedValue, radix);
            return new BlockType(value, blockNumber);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid block value: " + value, e);
        }
```
