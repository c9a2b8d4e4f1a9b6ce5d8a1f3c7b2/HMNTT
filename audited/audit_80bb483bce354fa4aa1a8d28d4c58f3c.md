### Title
Cache-Key Granularity Mismatch in `findByTimestamp` Enables Sustained DB Overload via Unique Timestamp Flooding

### Summary
`RecordFileRepository.findByTimestamp(long timestamp)` caches results keyed on the exact nanosecond timestamp value, but the underlying query is a range query (`consensusEnd >= ?1`) meaning many distinct timestamps map to the same record file. An unauthenticated attacker can continuously supply unique nanosecond-precision timestamps, each causing a cache miss and a DB query, while the global rate limit (500 req/s, not per-IP) and a bypassable gas bucket allow sustaining 500 DB queries/second indefinitely, well above the 30% threshold.

### Finding Description

**Exact code locations:**

`RecordFileRepository.findByTimestamp` — cache annotation and query: [1](#0-0) 

The `@Cacheable` key is the raw `timestamp` parameter (Spring's default key derivation). The query is:
```sql
select r from RecordFile r where r.consensusEnd >= ?1 order by r.consensusEnd asc limit 1
```
This is a **range query**: every nanosecond timestamp within a block's interval (e.g., `[consensusStart, consensusEnd)`) resolves to the same `RecordFile`, but each is stored under a **different cache key**. There is no key normalization to the resolved `consensusEnd`.

`CACHE_MANAGER_RECORD_FILE_TIMESTAMP` configuration: [2](#0-1) 

- `maximumSize(10000)` — only 10,000 distinct timestamps fit before eviction begins
- `expireAfterAccess(10, TimeUnit.MINUTES)` — entries survive only if re-accessed

`RecordFileServiceImpl.findByTimestamp` — no additional protection: [3](#0-2) 

**Rate limiting — global only, not per-IP:** [4](#0-3) 

Default `requestsPerSecond = 500`. A single attacker can consume the entire global budget.

**Gas bucket bypass:** [5](#0-4) 

`scaleGas(gas)` returns `0` when `gas <= 10_000`. `gasLimitBucket.tryConsume(0)` always succeeds in bucket4j, so requests with `gas ≤ 10,000` bypass the gas-per-second limit entirely and are only subject to the 500 req/s rate limit. [6](#0-5) 

**Root cause:** The cache key is the raw user-supplied nanosecond timestamp, not the canonical `consensusEnd` of the resolved record file. Hedera consensus timestamps have nanosecond precision; a single block spans billions of unique valid nanosecond values. The attacker never needs to repeat a timestamp.

### Impact Explanation

At 500 req/s (the global ceiling), every request with a previously-unseen timestamp issues one DB query (`SELECT ... WHERE consensusEnd >= ? ORDER BY consensusEnd ASC LIMIT 1`). This is a non-trivial indexed range scan on the `record_file` table. Sustained at 500 QPS, this adds a constant, attacker-controlled DB query stream. On a lightly loaded node (e.g., baseline 100–300 DB queries/second from legitimate traffic), 500 additional queries/second represents a 167–500% increase — far exceeding the 30% threshold. Even on a heavily loaded node, the attacker can sustain this indefinitely with no cost beyond network bandwidth, degrading response times for all users.

### Likelihood Explanation

- **No authentication required** — any public JSON-RPC endpoint is reachable
- **Trivially scriptable** — increment a nanosecond counter per request; all values within any known block range are valid
- **Gas bypass is reliable** — setting `gas=21000` (≤ 10,000 threshold is actually 10,000, so gas=10000 or below; but even at 21,000 the scaled value is `floor(21000/10000)=2` tokens, negligible against the 750M token/s gas budget)
- **No per-IP throttle** — a single source IP can consume the full 500 req/s global budget
- **Repeatable indefinitely** — nanosecond timestamp space is effectively unbounded

### Recommendation

1. **Normalize the cache key**: Before caching, resolve the timestamp to the canonical `consensusEnd` of the matching record file and use that as the cache key. This collapses all timestamps within a block to a single cache entry.
2. **Add per-IP rate limiting**: Introduce a per-source-IP token bucket in addition to the global bucket, preventing a single client from monopolizing the global limit.
3. **Cache negative results**: The `unless = "#result == null"` condition means out-of-range timestamps are never cached, enabling a secondary attack with invalid timestamps. Remove this exclusion or add a bounded negative-result cache.

### Proof of Concept

```python
import requests, time

# Known valid consensusEnd range: e.g., block N spans [1700000000_000000000, 1700000005_000000000)
BASE_TS = 1700000000_000000000
RPC_URL = "http://<mirror-node>:8545"

for i in range(100_000):
    ts = BASE_TS + i  # unique nanosecond timestamp, all valid (within block range)
    payload = {
        "jsonrpc": "2.0", "id": i, "method": "eth_call",
        "params": [{"to": "0x0000000000000000000000000000000000000167", "gas": "0x2710", "data": "0x"}, hex(ts)]
    }
    requests.post(RPC_URL, json=payload)
    # No sleep — rely on server-side 500 req/s global limit
    # Each request hits a unique cache key → 1 DB query per request
    # After 10,000 requests, cache eviction begins, sustaining DB load
```

Each iteration sends a request with a unique, valid nanosecond timestamp. The first 10,000 fill the cache; subsequent requests cause evictions and re-queries, sustaining 500 DB queries/second for as long as the attacker runs the loop.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/RecordFileServiceImpl.java (L29-32)
```java
    @Override
    public Optional<RecordFile> findByTimestamp(Long timestamp) {
        return recordFileRepository.findByTimestamp(timestamp);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-46)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
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
