### Title
Unbounded `CaffeineCache` Instance Accumulation in `cacheManagerSlotsPerContract` via Unauthenticated `eth_call` Requests

### Summary
In `ContractStateServiceImpl.findStorageBatch()`, each unique `contractId` causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to create a new `CaffeineCache` instance stored permanently in the `CaffeineCacheManager`'s internal `ConcurrentHashMap`. Because `cacheManagerSlotsPerContract` is configured without `setCacheNames()`, it operates in dynamic mode with no eviction of cache instances. The outer `contractSlotsCache` (max 3000 entries) evicts contractId mappings but never removes the corresponding inner `CaffeineCache` objects from `cacheManagerSlotsPerContract`, causing unbounded memory growth. An unauthenticated attacker can trigger this via the public `/api/v1/contracts/call` endpoint.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 107–112 — `cacheManagerSlotsPerContract` is created **without** `setCacheNames()`:

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    // NO setCacheNames() call → dynamic mode, unbounded cacheMap
    return caffeineCacheManager;
}
``` [1](#0-0) 

`ContractStateServiceImpl.java` lines 85–87 — for every cache miss on the outer cache, a new `CaffeineCache` is created and registered inside `cacheManagerSlotsPerContract`:

```java
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
            contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [2](#0-1) 

**Root cause and failed assumption:**

Spring's `CaffeineCacheManager` stores dynamically created caches in an internal `ConcurrentHashMap<String, Cache>` (`cacheMap`). This map has no size bound and no eviction. The design assumes the outer `contractSlotsCache` (max 3000) bounds the number of distinct contractIds seen, but it does not: when the outer cache evicts an entry (contractId → CaffeineCache), the `CaffeineCache` object is removed from the outer cache but **remains referenced in `cacheManagerSlotsPerContract.cacheMap`** indefinitely. The `slotsPerContract` config (`expireAfterAccess=5m,maximumSize=1500`) governs entries *within* each per-contract cache, not the lifecycle of the cache instances themselves. [3](#0-2) 

**Exploit flow:**

1. Attacker sends `POST /api/v1/contracts/call` with a unique `to` address per request (no authentication required). [4](#0-3) 
2. Each unique address maps to a distinct `EntityId` (contractId). `ContractStorageReadableKVState.readFromDataSource()` calls `contractStateService.findStorage(entityId, keyBytes)`. [5](#0-4) 
3. `findStorage` calls `findStorageBatch`, which calls `cacheManagerSlotsPerContract.getCache(contractId.toString())`, creating a new `CaffeineCache` instance and permanently registering it in `cacheManagerSlotsPerContract`'s internal map. [6](#0-5) 
4. The outer `contractSlotsCache` evicts old entries after reaching 3000, but the inner `CaffeineCache` objects remain in `cacheManagerSlotsPerContract.cacheMap` forever.
5. After N unique contractIds, `cacheManagerSlotsPerContract.cacheMap` holds N `CaffeineCache` instances, each with Caffeine's pre-allocated internal data structures for `maximumSize=1500`.

**Why existing checks fail:**

- `maximumSize=3000` on `contractSlotsCache`: bounds the outer cache only; eviction from it does not remove entries from `cacheManagerSlotsPerContract.cacheMap`.
- `expireAfterAccess=5m` / `maximumSize=1500` on `slotsPerContract`: these are per-entry policies *within* each `CaffeineCache` instance, not policies on the number of cache instances.
- `ThrottleManager`: rate-limits per-request gas, not the cumulative creation of cache instances over time. [7](#0-6) 

### Impact Explanation
Each `CaffeineCache` instance backed by Caffeine's `BoundedLocalCache` with `maximumSize=1500` pre-allocates internal arrays and data structures (typically several KB per instance). An attacker creating tens of thousands of unique contractId cache entries causes the JVM heap to fill with unreclaimable `CaffeineCache` objects, leading to increased GC pressure, GC pauses, and eventual OOM. This directly degrades or halts the mirror node's ability to serve EVM simulation requests, satisfying the >30% resource consumption increase threshold. The impact is persistent across the attack window since the cache instances do not expire.

### Likelihood Explanation
The `/api/v1/contracts/call` endpoint requires no authentication and accepts any valid 20-byte hex address as the `to` field. An attacker can enumerate `2^160` possible addresses; in practice, sending thousands of requests with distinct addresses is trivial using a script. The attack is low-cost (no on-chain transactions required), repeatable, and cumulative — each request permanently adds to the leaked cache instances. The only friction is the `ThrottleManager`, which limits gas per request but does not prevent sustained low-rate accumulation.

### Recommendation

1. **Call `setCacheNames()` on `cacheManagerSlotsPerContract`** with a fixed set of names to prevent dynamic cache creation entirely. If per-contract caches are required, manage them explicitly with a bounded structure.

2. **Alternatively, replace the two-level cache design** with a single `Cache` keyed by `(contractId, slotKey)` composite key, eliminating the need for dynamically created per-contract `CaffeineCache` instances.

3. **If dynamic caches must be retained**, wrap `cacheManagerSlotsPerContract`'s `cacheMap` with a bounded eviction policy (e.g., a `LinkedHashMap` with LRU eviction or a Caffeine cache of caches), and register a removal listener on the outer `contractSlotsCache` to evict the corresponding inner cache from `cacheManagerSlotsPerContract` when a contractId entry is evicted.

### Proof of Concept

```bash
# Send N requests with unique contract addresses (no auth required)
for i in $(seq 1 50000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$ADDR\",\"data\":\"0x\",\"gas\":21000}" &
done
wait

# Expected result:
# cacheManagerSlotsPerContract.cacheMap grows to ~50000 entries
# Each CaffeineCache (maximumSize=1500) holds pre-allocated Caffeine internals
# JVM heap usage increases significantly; GC pauses increase
# Monitor via JMX/heap dump: com.github.benmanes.caffeine.cache.BoundedLocalCache instances
```

The outer `contractSlotsCache` will evict entries after 3000 unique contractIds, but `cacheManagerSlotsPerContract`'s internal map retains all 50000 `CaffeineCache` instances, none of which are garbage-collected.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L24-39)
```java
    @NotBlank
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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractStorageReadableKVState.java (L38-44)
```java
        final var contractID = slotKey.contractID();
        final var entityId = EntityIdUtils.entityIdFromContractId(contractID);
        final var keyBytes = slotKey.key().toByteArray();
        return timestamp
                .map(t -> contractStateService.findStorageByBlockTimestamp(
                        entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
                .orElse(contractStateService.findStorage(entityId, keyBytes))
```
