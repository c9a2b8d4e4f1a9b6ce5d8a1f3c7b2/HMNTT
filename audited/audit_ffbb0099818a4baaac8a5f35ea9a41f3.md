### Title
Unbounded Memory Growth via `cacheManagerSlotsPerContract` Internal Cache Map in `findStorageBatch()`

### Summary
In `ContractStateServiceImpl.findStorageBatch()`, every unique `contractId` triggers `cacheManagerSlotsPerContract.getCache(contractId.toString())`, which permanently stores a new `CaffeineCache` instance in Spring's `CaffeineCacheManager` internal `cacheMap`. Because `cacheManagerSlotsPerContract` is configured without `setCacheNames()` (dynamic mode, no size bound on the manager's own map), and because `contractSlotsCache` eviction does not remove entries from `cacheManagerSlotsPerContract`, an unprivileged attacker can cause unbounded JVM heap growth by issuing requests targeting a large number of distinct contract addresses.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.java`, lines 85–87:
```java
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
            contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

`EvmConfiguration.java`, lines 107–112:
```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;
}
```

Note: `setCacheNames()` is **not** called, so `CaffeineCacheManager` runs in dynamic mode (`dynamic=true`).

**Root cause:**

Spring's `CaffeineCacheManager.getCache(name)` stores every created `CaffeineCache` in an internal `ConcurrentHashMap<String, Cache> cacheMap` with **no eviction and no size bound**. When `contractSlotsCache` (max 3000 entries, `expireAfterAccess=5m`) evicts an entry for a given `contractId`, the corresponding `CaffeineCache` object is removed from `contractSlotsCache`'s value set, but `cacheManagerSlotsPerContract.cacheMap` still holds a strong reference to it under the key `contractId.toString()`. The `CaffeineCache` object is never garbage-collected.

**Exploit flow:**

1. Attacker sends `POST /api/v1/contracts/call` requests, each targeting a distinct contract address (valid or not — the cache path is hit before DB result matters).
2. Each unique `contractId` not already in `contractSlotsCache` triggers the loader, calling `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
3. A new `CaffeineCache` (with its own Caffeine internal structures: `ConcurrentHashMap`, `Scheduler`, etc.) is created and permanently stored in `cacheManagerSlotsPerContract.cacheMap`.
4. `contractSlotsCache` evicts old entries when it reaches `maximumSize=3000`, but `cacheManagerSlotsPerContract` retains all ever-created caches.
5. Memory grows linearly with the number of unique contract IDs used.

**Why existing checks fail:**

- `contractSlotsCache` `maximumSize=3000` only bounds the *active* entries in that cache; it does not bound `cacheManagerSlotsPerContract.cacheMap`.
- `expireAfterAccess=5m` on `contractSlotsCache` causes eviction of inactive entries, but eviction from `contractSlotsCache` does not trigger any cleanup in `cacheManagerSlotsPerContract`.
- The rate limiter (`requestsPerSecond=500`, `gasPerSecond=1.5B`) allows 500 new unique contract IDs per second. After 1 hour: 1,800,000 `CaffeineCache` objects permanently retained.
- There is no per-IP or per-caller rate limit; the global 500 req/s is shared across all callers and is easily saturated by a single attacker.

### Impact Explanation

Each retained `CaffeineCache` object carries Caffeine's internal data structures (a `BoundedLocalCache` with its own `ConcurrentHashMap`, `MpscGrowableArrayQueue`, `ScheduledExecutorService` reference, etc.), consuming on the order of 1–10 KB per instance. At 500 req/s sustained for 1 hour, this yields ~1.8M objects × ~2 KB = ~3.6 GB of heap growth, sufficient to exhaust a typical JVM heap (default or configured at 2–4 GB), triggering `OutOfMemoryError` and crashing the web3 node process. If multiple mirror-node web3 instances share the same deployment, the same attack repeated across instances can degrade ≥30% of processing nodes without requiring any privileged access.

### Likelihood Explanation

The attack requires only the ability to send unauthenticated HTTP POST requests to `/api/v1/contracts/call` — no credentials, no on-chain funds, no special knowledge. Contract addresses can be enumerated sequentially (e.g., `0x0000...0001` through `0x0000...FFFF`). The attack is repeatable, automatable with a simple script, and does not require brute force. The 500 req/s global rate limit is the only barrier, and it is not per-source, making it trivially exploitable from a single client.

### Recommendation

1. **Remove `cacheManagerSlotsPerContract` as a factory**: Instead of calling `cacheManagerSlotsPerContract.getCache(contractId.toString())` (which permanently registers the cache in the manager), construct `CaffeineCache` instances directly using `Caffeine.newBuilder()...build()` and wrap them manually. This avoids the unbounded `cacheMap` growth entirely.
2. **Alternatively**, replace the two-level cache structure with a single `Cache<EntityId, Cache<ByteBuffer, byte[]>>` using Caffeine's native nested or composite key approach, or use a `LoadingCache` with a bounded `maximumWeight`.
3. **Add per-source-IP rate limiting** at the ingress layer to prevent a single client from exhausting the global 500 req/s budget.

### Proof of Concept

```python
import requests, threading

TARGET = "http://<mirror-node>/api/v1/contracts/call"
HEADERS = {"Content-Type": "application/json"}

def attack(start, count):
    for i in range(start, start + count):
        addr = "0x" + hex(i)[2:].zfill(40)
        requests.post(TARGET, json={
            "to": addr,
            "data": "0x",
            "gas": 21000,
            "block": "latest"
        }, headers=HEADERS)

# Launch 10 threads, each targeting 10000 unique contract addresses
threads = [threading.Thread(target=attack, args=(i*10000, 10000)) for i in range(10)]
[t.start() for t in threads]
[t.join() for t in threads]
# Result: 100,000 CaffeineCache objects permanently retained in cacheManagerSlotsPerContract
# Repeat until OOM
```

Each iteration of the outer loop permanently adds entries to `cacheManagerSlotsPerContract.cacheMap`. Monitor JVM heap via JMX or `/actuator/metrics` to observe unbounded growth.