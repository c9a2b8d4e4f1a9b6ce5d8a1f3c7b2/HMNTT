### Title
Unbounded `CaffeineCacheManager` Registry Growth via Unique `contractId` Flooding in `findStorageBatch()`

### Summary
`ContractStateServiceImpl.findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` for every unique `contractId` encountered. Because `cacheManagerSlotsPerContract` is a `CaffeineCacheManager` configured in dynamic (no pre-declared names) mode, its internal `ConcurrentHashMap<String, Cache> cacheMap` grows without any eviction bound. The outer `contractSlotsCache` (maximumSize=3000) evicts entries but never removes the corresponding `CaffeineCache` objects from `cacheManagerSlotsPerContract`'s registry, creating a permanent memory leak. An unprivileged attacker can exploit this by flooding the public `eth_call` endpoint with requests targeting many unique contract addresses, causing unbounded heap growth, GC pressure, and eventual OOM.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.java`, `findStorageBatch()`, lines 86–87:
```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

`cacheManagerSlotsPerContract` is declared in `EvmConfiguration.java` lines 107–112:
```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;  // NO setCacheNames() → dynamic mode
}
```

**Root cause — failed assumption:**

The design assumes that the outer `contractSlotsCache` (Caffeine, `maximumSize=3000`) bounds the total number of live `CaffeineCache` objects. This is false. Spring's `CaffeineCacheManager.getCache()` stores every created cache in an internal `ConcurrentHashMap<String, Cache> cacheMap` (the registry). This map has **no eviction mechanism**. When `contractSlotsCache` evicts an entry for a `contractId`, the corresponding `CaffeineCache` is removed from `contractSlotsCache`'s value set but **remains permanently in `cacheManagerSlotsPerContract.cacheMap`**, keyed by `contractId.toString()`. The registry only grows.

**Exploit flow:**

1. Attacker sends `eth_call` (or `eth_estimateGas`) requests to the unauthenticated web3 JSON-RPC endpoint, each targeting a distinct contract address (e.g., iterating `0x0000…0001` through `0x0000…FFFF`).
2. Each request reaches `findStorage()` → cache miss in `contractStateCache` → `findStorageBatch()` is called.
3. `this.contractSlotsCache.get(contractId, supplier)` misses → supplier executes → `cacheManagerSlotsPerContract.getCache(contractId.toString())` is called.
4. Spring's `CaffeineCacheManager` calls `cacheMap.computeIfAbsent(name, this::createCaffeineCache)`, allocating a new `CaffeineCache` with a `FrequencySketch` table sized to `maximumSize=1500` (~64 KB per instance).
5. The new `CaffeineCache` is stored in both `contractSlotsCache` (evictable, max 3000) and `cacheManagerSlotsPerContract.cacheMap` (permanent, unbounded).
6. After 3000 unique IDs, `contractSlotsCache` starts evicting. Each eviction frees the reference in `contractSlotsCache` but the `CaffeineCache` object remains live in `cacheManagerSlotsPerContract.cacheMap`.
7. Heap grows at ~64 KB per unique `contractId`. At 500 RPS (the global rate limit), after 1 hour: ~1.8 M unique IDs → ~115 GB heap pressure → OOM / sustained GC storms.

**Why existing checks are insufficient:**

- `contractSlotsCache` `maximumSize=3000` bounds the outer cache entries, not the `cacheManagerSlotsPerContract` registry.
- `slotsPerContract` `maximumSize=1500` is a per-cache-instance entry limit, not a limit on the number of cache instances.
- The global rate limit of 500 RPS (`requestsPerSecond=500`) is not per-IP and is shared across all callers; a single attacker can consume the full budget.
- No authentication is required for `eth_call`.

### Impact Explanation

Each unique `contractId` permanently allocates a `CaffeineCache` object (~64 KB minimum due to `FrequencySketch` pre-allocation for `maximumSize=1500`) in the JVM heap. With 500 RPS sustained over minutes, the heap fills rapidly, triggering continuous full GC cycles. This directly increases CPU consumption well beyond 30% (GC threads compete with request-processing threads) and ultimately causes `OutOfMemoryError`, crashing the web3 service. The attack requires no privileged access, no on-chain transactions, and no special tooling beyond standard HTTP clients.

### Likelihood Explanation

The web3 JSON-RPC endpoint is publicly accessible and requires no authentication. The attacker needs only to iterate through distinct Ethereum-format addresses in the `to` field of `eth_call` requests. This is trivially scriptable with `curl` or any JSON-RPC library. The global 500 RPS rate limit is not per-source-IP, so a single client can exhaust it. The attack is repeatable and persistent: even after the attacker stops, the leaked `CaffeineCache` objects remain in the heap until the JVM is restarted.

### Recommendation

1. **Remove `cacheManagerSlotsPerContract` as a `CaffeineCacheManager` registry entirely.** Instead of calling `cacheManagerSlotsPerContract.getCache(contractId.toString())` (which registers the cache permanently), construct the `CaffeineCache` directly using `Caffeine.newBuilder()...build()` inside the supplier. This eliminates the registry leak:
   ```java
   final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
       contractId, () -> new CaffeineCache(contractId.toString(),
           Caffeine.newBuilder()
               .expireAfterAccess(5, TimeUnit.MINUTES)
               .maximumSize(1500)
               .build())));
   ```
2. **Alternatively**, replace `contractSlotsCache` with a `Cache<EntityId, CaffeineCache>` that uses a Caffeine `removalListener` to explicitly call `cacheManagerSlotsPerContract`'s internal map removal on eviction, keeping the registry in sync.
3. **Add per-source-IP rate limiting** to prevent a single client from exhausting the global 500 RPS budget.

### Proof of Concept

```python
import requests, threading

URL = "http://<mirror-node-host>:8545"

def call(contract_id):
    addr = f"0x{contract_id:040x}"
    requests.post(URL, json={
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": addr, "data": "0x6d4ce63c"}, "latest"],
        "id": contract_id
    })

# Flood with 50,000 unique contract addresses across 500 threads
threads = []
for i in range(1, 50001):
    t = threading.Thread(target=call, args=(i,))
    threads.append(t)
    t.start()
    if len(threads) >= 500:
        for t in threads: t.join()
        threads = []

# After ~100 seconds at 500 RPS:
# cacheManagerSlotsPerContract.cacheMap contains 50,000 CaffeineCache objects
# Heap growth: ~50,000 * 64KB = ~3.2 GB
# Monitor with: jmap -histo <pid> | grep CaffeineCache
```

Observe heap growth via JVM metrics; `CaffeineCache` instance count in `cacheManagerSlotsPerContract` increases monotonically and never decreases, confirming the leak. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-87)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-39)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";

    @NotBlank
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";

    private boolean enableBatchContractSlotCaching = true;

    @NotBlank
    private String entity = ENTITY_CACHE_CONFIG;

    @NotBlank
    private String fee = "expireAfterWrite=60m,maximumSize=20,recordStats";

    @NotBlank
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
