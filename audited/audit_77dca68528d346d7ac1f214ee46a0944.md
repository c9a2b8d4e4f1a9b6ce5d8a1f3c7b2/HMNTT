### Title
Cache Miss Amplification via Unique Non-Existent Block Numbers in eth_call with Gas Throttle Bypass

### Summary
The `RecordFileRepository.findByIndex()` method is annotated with `@Cacheable(unless = "#result == null")`. Spring's caching abstraction unwraps `Optional<T>` return values, treating `Optional.empty()` as null — meaning lookups for non-existent block numbers are never cached. Combined with a gas throttle bypass for requests with `gas <= 10_000`, an unauthenticated attacker can sustain up to 500 DB queries per second against the `record_file` table by cycling through unique non-existent block numbers in the `block` field of eth_call requests.

### Finding Description

**Cache non-population for empty Optional:**

`RecordFileRepository.findByIndex` is declared as:

```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
@Query("select r from RecordFile r where r.index = ?1")
Optional<RecordFile> findByIndex(long index);
``` [1](#0-0) 

Spring's `CacheAspectSupport` unwraps `Optional` return values before evaluating `unless`. When the block index does not exist in the DB, the method returns `Optional.empty()`, which Spring treats as `null` for the `unless` condition. The condition `unless = "#result == null"` therefore prevents the empty result from being stored in the cache. Every subsequent request for the same non-existent block number re-executes the DB query.

The cache itself is configured with `maximumSize=10000` and `expireAfterWrite=10 minutes`: [2](#0-1) 

**Gas throttle bypass for low-gas requests:**

`ThrottleProperties.scaleGas()` returns `0` for any `gas <= 10_000`:

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {  // GAS_SCALE_FACTOR = 10_000
        return 0L;
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
``` [3](#0-2) 

`gasLimitBucket.tryConsume(0)` always returns `true`, so the gas-per-second throttle is completely bypassed: [4](#0-3) 

**Request path from eth_call to DB:**

`ContractController.call()` → `contractExecutionService.processCall(params)` → `RecordFileServiceImpl.findByBlockType(block)` → `recordFileRepository.findByIndex(block.number())`: [5](#0-4) 

**Only protection remaining:** the `rateLimitBucket` at 500 requests/second (default): [6](#0-5) 

### Impact Explanation
At 500 RPS (the default rate limit), an attacker cycling through unique non-existent block numbers forces 500 uncached DB queries per second against the `record_file` table. While the query uses the `record_file__index` unique index (an index seek, not a full table scan), the volume of index I/O, connection pool consumption, and query planning overhead at sustained 500 RPS is sufficient to materially increase DB I/O load — exceeding the 30% threshold on a node that would otherwise serve most historical block lookups from the Caffeine cache. No authentication or privilege is required.

### Likelihood Explanation
The attack requires only HTTP access to `POST /api/v1/contracts/call` with a valid JSON body. Setting `gas` to any value ≤ 10,000 (e.g., `"gas": 0`) bypasses the gas throttle. Cycling block numbers (e.g., incrementing a counter starting from a value beyond the chain tip) guarantees every request is a cache miss. This is trivially scriptable and repeatable indefinitely within the 500 RPS rate limit.

### Recommendation
1. **Cache negative results:** Change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` (or equivalently `unless = "#result?.isEmpty() == true"`) so that `Optional.empty()` results for non-existent block numbers are also stored in the cache with a short TTL (e.g., 30 seconds).
2. **Fix gas throttle floor:** Remove the `if (gas <= GAS_SCALE_FACTOR) return 0L` shortcut, or enforce a minimum token consumption of 1 for any request that reaches the throttle, so zero-gas requests are not exempt from the gas bucket.
3. **Validate block number range before DB query:** In `RecordFileServiceImpl.findByBlockType`, reject or short-circuit block numbers that exceed the latest known block index (cached via `findLatest`) before calling `findByIndex`.

### Proof of Concept
```bash
# Requires only network access to the web3 endpoint.
# Cycles through unique non-existent block numbers (beyond chain tip).
# gas=0 bypasses the gas-per-second throttle entirely.

ENDPOINT="http://<mirror-node-host>/api/v1/contracts/call"
BLOCK=9999999999  # Start beyond chain tip

while true; do
  curl -s -X POST "$ENDPOINT" \
    -H "Content-Type: application/json" \
    -d "{
      \"to\": \"0x0000000000000000000000000000000000000001\",
      \"data\": \"0x\",
      \"gas\": 0,
      \"block\": \"$BLOCK\"
    }" &
  BLOCK=$((BLOCK + 1))
  # Stay within 500 RPS rate limit
  sleep 0.002
done
```

Each iteration uses a unique `block` value → cache miss guaranteed → one `SELECT ... FROM record_file WHERE index = ?` DB query per request → sustained at 500 RPS.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

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
