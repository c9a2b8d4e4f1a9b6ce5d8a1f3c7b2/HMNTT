### Title
Unbounded `CaffeineCacheManager` Internal Registry Growth via Unprivileged `eth_call` Requests

### Summary
`cacheManagerSlotsPerContract()` creates a `CaffeineCacheManager` in dynamic mode (no `setCacheNames()` call), causing its internal `cacheMap` (`ConcurrentHashMap<String, Cache>`) to grow permanently for every unique contract ID passed to `getCache()`. The outer `contractSlots` cache (maximumSize=3000) evicts entries but never removes the corresponding `CaffeineCache` instances from the `CaffeineCacheManager`'s registry, resulting in unbounded heap growth exploitable by any unauthenticated caller of the public `eth_call` endpoint.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — `cacheManagerSlotsPerContract()` creates a `CaffeineCacheManager` without calling `setCacheNames()`:

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;
}
``` [1](#0-0) 

Omitting `setCacheNames()` leaves `CaffeineCacheManager` in **dynamic mode**, where any call to `getCache(name)` with a previously unseen name creates a new `CaffeineCache` and stores it permanently in the manager's internal `ConcurrentHashMap<String, Cache> cacheMap`.

`ContractStateServiceImpl.java` lines 85–87 — for every unique `contractId` not already in the outer cache, the loader fires and calls `cacheManagerSlotsPerContract.getCache(contractId.toString())`:

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [2](#0-1) 

**Root cause and failed assumption:**

The design assumes that the outer `contractSlots` cache (`maximumSize=3000`) bounds memory by evicting `CaffeineCache` values when capacity is exceeded. This assumption is wrong. Spring's `CaffeineCacheManager.cacheMap` holds a **strong reference** to every `CaffeineCache` it has ever created; eviction from the outer Caffeine cache removes the entry from that cache's table but does **not** call back into `CaffeineCacheManager` to remove the entry from `cacheMap`. The `cacheMap` therefore grows monotonically.

The `maximumSize=1500` in `slotsPerContract = "expireAfterAccess=5m,maximumSize=1500"` limits the number of **slot keys per individual contract cache**, not the number of contract caches that can be registered. [3](#0-2) 

**Exploit flow:**

1. Attacker sends `eth_call` (or `estimateGas`) requests, each targeting a different contract address (or contract entity ID).
2. Each request reaches `findStorageBatch` → outer `contractSlotsCache.get(contractId, loader)` misses → loader calls `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
3. `CaffeineCacheManager` creates a new `CaffeineCache` backed by a full Caffeine cache instance (pre-allocated internal structures for up to 1500 entries) and inserts it into `cacheMap`.
4. When the outer cache reaches 3000 entries it evicts the oldest `CaffeineCache` value — but `cacheMap` retains the reference. The evicted `CaffeineCache` is never GC'd.
5. Repeating with N distinct contracts leaves N entries in `cacheMap`, each holding a live Caffeine cache object.

### Impact Explanation

Each Caffeine cache instance allocated with `maximumSize=1500` carries non-trivial heap overhead (internal node arrays, scheduler references, statistics objects). At the default rate limit of 500 RPS, an attacker can register ~500 new contract caches per second. After one hour of sustained attack (~1.8 M unique contracts), the `cacheMap` holds 1.8 M live `CaffeineCache` objects. This causes progressive heap exhaustion, eventually triggering `OutOfMemoryError` and crashing the web3 service — a complete denial of service. Even at lower rates the heap pressure degrades GC performance and increases latency well above the 30% threshold stated in the scope.

### Likelihood Explanation

The `eth_call` / `estimateGas` endpoints are public and require no authentication. Contract addresses on Hedera are sequential entity IDs, so an attacker can trivially enumerate thousands of valid contract IDs. No special privileges, tokens, or on-chain transactions are required — only HTTP POST requests to the mirror node's web3 API. The attack is fully repeatable and can be automated with a simple script. The rate limit of 500 RPS (`hiero.mirror.web3.throttle.requestsPerSecond=500`) does not prevent the attack; it only determines how quickly the heap fills. [4](#0-3) 

### Recommendation

1. **Pre-register cache names** — call `setCacheNames(Set.of(...))` in `cacheManagerSlotsPerContract()` with a fixed set of names, disabling dynamic mode entirely. Because the per-contract cache name is a runtime value (the contract entity ID), this requires a different design.

2. **Preferred fix — remove the `CaffeineCacheManager` indirection** — instead of using `CaffeineCacheManager.getCache(contractId)` to obtain a per-contract cache, store the `CaffeineCache` instances directly as values in the outer `contractSlots` Caffeine cache (which already has `maximumSize=3000`). Build each `CaffeineCache` inline using `Caffeine.newBuilder()...build()` inside the loader lambda, eliminating the `CaffeineCacheManager` registry entirely.

3. **Short-term mitigation** — wrap `cacheManagerSlotsPerContract` with a size-bounded registry (e.g., a `LinkedHashMap` with a max size and LRU eviction) so that the number of live `CaffeineCache` instances is capped.

### Proof of Concept

```python
import requests, threading

TARGET = "http://<mirror-node-host>:8545"
# Hedera contract entity IDs are sequential; use any range of valid IDs
CONTRACT_IDS = [f"0x{i:040x}" for i in range(1, 200_000)]

def call(addr):
    requests.post(TARGET, json={
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": addr, "data": "0x"}, "latest"],
        "id": 1
    }, timeout=5)

# Flood with distinct contract addresses to fill cacheMap
with threading.ThreadPoolExecutor(max_workers=50) as ex:
    ex.map(call, CONTRACT_IDS)

# Monitor heap via JMX/actuator: cacheMap in CaffeineCacheManager
# for bean "slotsPerContract" grows without bound; heap usage climbs
# proportionally until OOM or >30% baseline increase is observed.
```

Each iteration of the loop registers a new permanent entry in `CaffeineCacheManager.cacheMap` for the `slotsPerContract` bean, with no eviction path.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** docs/configuration.md (L730-730)
```markdown
| `hiero.mirror.web3.throttle.requestsPerSecond`               | 500                                                | Maximum RPS limit                                                                                                                                                                                |
```
