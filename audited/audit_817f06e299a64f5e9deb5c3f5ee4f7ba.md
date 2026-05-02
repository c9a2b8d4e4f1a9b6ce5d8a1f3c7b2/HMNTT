### Title
Unbounded `CaffeineCacheManager` Internal Map Growth via Dynamic Cache Creation in `cacheManagerSlotsPerContract` Leads to JVM Heap Exhaustion (DoS)

### Summary
`cacheManagerSlotsPerContract()` omits `setCacheNames()`, leaving Spring's `CaffeineCacheManager` in dynamic mode. Every unique `contractId` ever queried causes a new named `CaffeineCache` to be permanently inserted into the manager's internal `ConcurrentHashMap<String, Cache>`. Because this map is never pruned — even when the outer `contractSlotsCache` evicts entries — an unprivileged attacker can exhaust JVM heap by issuing `eth_call` requests against a large number of distinct contract addresses, crashing the web3 service and blocking all fund transfers.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — the bean is created without `setCacheNames()`:
```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;   // dynamic=true, cacheMap unbounded
}
```

`ContractStateServiceImpl.java` line 87 — every cache miss on the outer `contractSlotsCache` calls `getCache(contractId.toString())` on the dynamic manager:
```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**Root cause:** Spring's `CaffeineCacheManager.getCache(name)` stores newly created caches in a `ConcurrentHashMap<String, Cache> cacheMap`. When `setCacheNames()` is not called, `dynamic = true` and every new name permanently adds an entry. There is no eviction, expiry, or size cap on `cacheMap` itself.

**Why the outer bound does not help:** The outer `contractSlotsCache` (bean `contractSlots`) is configured with `maximumSize=3000, expireAfterAccess=5m`. When a `contractId` is evicted from `contractSlotsCache`, the value loader `() -> cacheManagerSlotsPerContract.getCache(contractId.toString())` is simply not called again for that key — but the named cache already inserted into `cacheManagerSlotsPerContract.cacheMap` is **never removed**. The `cacheMap` accumulates one entry per unique `contractId` ever seen, growing monotonically for the lifetime of the JVM.

**Exploit flow:**
1. Attacker sends `eth_call` (or equivalent JSON-RPC) requests targeting N distinct contract addresses (existing or non-existent — the storage lookup path is reached regardless).
2. Each unique `contractId` that misses `contractSlotsCache` triggers `cacheManagerSlotsPerContract.getCache(contractId.toString())`.
3. Spring's `CaffeineCacheManager` inserts a new `CaffeineCache` (+ underlying Caffeine cache structure) into `cacheMap`.
4. After 3000 entries, `contractSlotsCache` starts evicting old `contractId`s, but `cacheManagerSlotsPerContract.cacheMap` retains all of them.
5. With enough unique IDs, `cacheMap` exhausts heap → `OutOfMemoryError` → JVM crash or severe GC thrashing → service unavailable.

### Impact Explanation
The web3 service becomes unavailable, preventing all `eth_call`, `eth_sendRawTransaction`, and balance-query operations. Any in-flight or pending fund transfers that rely on the mirror node's web3 endpoint fail. The impact is a complete denial of service of the Ethereum-compatible API layer with no data corruption, but full availability loss for the duration of the attack (until the process is restarted, at which point the attack can be immediately repeated).

### Likelihood Explanation
No authentication or special privilege is required — any caller of the public JSON-RPC endpoint can trigger this. The default throttle (`requestsPerSecond=500`) slows but does not prevent the attack: at 500 req/s, an attacker can register ~500 new `cacheMap` entries per second. With a typical JVM heap of 512 MB–2 GB and each `CaffeineCache` entry consuming ~2–10 KB of overhead, heap exhaustion is reachable in minutes to tens of minutes. The attack is trivially repeatable after each service restart.

### Recommendation
Add `setCacheNames()` to `cacheManagerSlotsPerContract()` with the single cache name actually used (the contract's `EntityId` string is used as a *key* inside the outer `contractSlotsCache`, not as a cache name — the manager only ever needs one named cache):

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME)); // disables dynamic creation
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;
}
```

Alternatively, refactor `findStorageBatch` to stop using `cacheManagerSlotsPerContract.getCache(contractId.toString())` as a per-contract named cache and instead use a single cache keyed by `contractId` directly, consistent with how all other cache managers in the same file are configured.

### Proof of Concept
```
# Precondition: mirror-node web3 service running with default config
# Step 1: Generate N unique contract IDs (e.g., 0.0.1 through 0.0.500000)
# Step 2: For each ID, send an eth_call:
for i in $(seq 1 500000); do
  curl -s -X POST http://<mirror-node>:8545 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",
         \"params\":[{\"to\":\"$(printf '0x%040x' $i)\",\"data\":\"0x\"},\"latest\"],
         \"id\":$i}" &
done
# Each unique address causes cacheManagerSlotsPerContract.cacheMap to grow by one entry.
# After ~100,000–500,000 requests (depending on heap size), the JVM throws
# OutOfMemoryError and the service crashes or becomes unresponsive.
# Result: all subsequent eth_call / fund transfer requests fail with connection refused.
```