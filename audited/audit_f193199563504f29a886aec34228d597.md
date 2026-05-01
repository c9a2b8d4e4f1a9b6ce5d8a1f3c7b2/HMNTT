### Title
Unbounded `CaffeineCacheManager` Internal Map Growth via Unique ContractId Cycling — Heap-Exhaustion DoS

### Summary
In `ContractStateServiceImpl.findStorageBatch()`, each unique `contractId` triggers a call to `cacheManagerSlotsPerContract.getCache(contractId.toString())`, which creates a new `CaffeineCache` and stores it permanently in `CaffeineCacheManager`'s internal unbounded `ConcurrentHashMap<String, Cache> cacheMap`. The outer `contractSlotsCache` (bounded at `maximumSize=3000`) evicts entries but does **not** remove the corresponding `CaffeineCache` from `cacheManagerSlotsPerContract`'s internal map, causing permanent heap retention. An unauthenticated attacker cycling through unique contract addresses accumulates an unbounded number of live `CaffeineCache` objects in the JVM heap, leading to OOM or severe GC pressure.

### Finding Description

**Exact code location:**
`web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, lines 86–87:

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**Root cause — two-layer cache design with a broken eviction assumption:**

1. `this.contractSlotsCache` is a Caffeine cache (`CACHE_MANAGER_CONTRACT_SLOTS`) configured with `expireAfterAccess=5m,maximumSize=3000`. It maps `EntityId contractId → CaffeineCache`. [1](#0-0) 

2. On a cache miss, the lambda calls `cacheManagerSlotsPerContract.getCache(contractId.toString())`. `cacheManagerSlotsPerContract` is a `CaffeineCacheManager` bean configured with **no `setCacheNames()` call**, placing it in Spring's "dynamic" mode. [2](#0-1) 

3. In dynamic mode, Spring's `CaffeineCacheManager` maintains an internal `ConcurrentHashMap<String, Cache> cacheMap`. Every call to `getCache(name)` for a new name creates a `CaffeineCache` and inserts it into `cacheMap`. **This map is never bounded and never evicts entries.** [3](#0-2) 

4. When the outer `contractSlotsCache` evicts an entry for `contractId_X` (due to `maximumSize=3000` or TTL), the `CaffeineCache` object for `contractId_X` is no longer referenced by the outer cache. However, `cacheManagerSlotsPerContract.cacheMap` still holds a strong reference to it under the key `contractId_X.toString()`. The `CaffeineCache` is never GC'd. [4](#0-3) 

5. The `slotsPerContract` spec `expireAfterAccess=5m,maximumSize=1500` applies to entries *within* each per-contract `CaffeineCache` (slot keys), not to the number of caches held in `cacheManagerSlotsPerContract.cacheMap`. [5](#0-4) 

**Exploit flow:**
- Attacker sends `eth_call` / `eth_estimateGas` JSON-RPC requests targeting N distinct contract addresses (Hedera contract IDs are sequential integers, e.g. `0.0.1` through `0.0.N`).
- Each unique `contractId` not yet in `contractSlotsCache` triggers the lambda, calling `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
- A new `CaffeineCache` is created and inserted into `cacheManagerSlotsPerContract.cacheMap`.
- After 3000 unique contractIds, the outer cache starts evicting old entries, but `cacheManagerSlotsPerContract.cacheMap` retains all N caches.
- Memory grows linearly and without bound with N.

### Impact Explanation
Each retained `CaffeineCache` object carries internal Caffeine data structures (segment arrays, scheduler references, etc.) — even an empty cache has non-trivial overhead (typically several KB). At the default throttle of 500 RPS, an attacker can register ~500 new caches per second. Over one hour that is ~1.8 million `CaffeineCache` objects permanently held in heap. This causes progressive heap exhaustion, triggering `OutOfMemoryError` or sustained full-GC pauses that render the web3 service unresponsive. No contract state data needs to exist; the attacker only needs to reference distinct contract addresses. [6](#0-5) 

### Likelihood Explanation
- **No authentication required**: the JSON-RPC endpoint (`eth_call`, `eth_estimateGas`) is public.
- **No special knowledge required**: Hedera contract IDs are sequential integers; iterating them is trivial.
- **Rate limiting is insufficient**: the 500 RPS throttle slows but does not stop accumulation; the leak is permanent and cumulative across restarts only if the JVM is restarted.
- **Repeatable**: the attacker can sustain the attack indefinitely from a single machine or a small botnet.
- **No on-chain cost**: `eth_call` is a read-only simulation; no gas or HBAR is spent by the attacker.

### Recommendation
1. **Replace `CaffeineCacheManager` as a dynamic factory**: Instead of calling `cacheManagerSlotsPerContract.getCache(contractId.toString())` (which permanently registers the cache in the manager's internal map), construct `CaffeineCache` objects directly using `Caffeine.newBuilder()...build()` and wrap them in `CaffeineCache`. This bypasses the unbounded `cacheMap` entirely.
2. **Alternatively, use a bounded `LoadingCache<EntityId, CaffeineCache>`** as the outer cache with a proper removal listener that explicitly invalidates/discards the inner cache on eviction, ensuring no strong references are retained after eviction.
3. **Do not use `CaffeineCacheManager` for dynamic/per-key cache creation**: it is designed for a fixed, pre-declared set of named caches, not for unbounded dynamic name registration.

### Proof of Concept
```python
import requests, itertools, time

RPC_URL = "http://<mirror-node-web3>:8545"

def eth_call(contract_addr):
    payload = {
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": contract_addr, "data": "0x"}, "latest"],
        "id": 1
    }
    requests.post(RPC_URL, json=payload, timeout=5)

# Hedera contract IDs map to EVM addresses as 0x000...0<contractNum>
for i in itertools.count(1):
    addr = f"0x{i:040x}"
    try:
        eth_call(addr)
    except Exception:
        pass
    # At 500 RPS, ~1.8M unique CaffeineCache objects accumulate per hour
    # Monitor JVM heap: jcmd <pid> VM.native_memory or jmap -histo
    # Expected: CaffeineCache / BoundedLocalCache instances grow without bound
    # until OOM or GC thrashing causes service degradation
```

**Verification**: Attach a heap profiler (e.g., `jmap -histo:live <pid> | grep CaffeineCache`) before and after running the script for a few minutes. The count of `CaffeineCache` / `BoundedLocalCache` instances will grow proportionally to the number of unique contract addresses sent, and will not decrease even after the 5-minute TTL window passes.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-25)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L38-39)
```java
    @NotBlank
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-87)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```
