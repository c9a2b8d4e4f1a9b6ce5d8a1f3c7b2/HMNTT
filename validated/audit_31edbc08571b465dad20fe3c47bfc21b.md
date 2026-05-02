The code has been verified against all claims. Here is the result:

---

Audit Report

## Title
Unbounded Memory Growth via `cacheManagerSlotsPerContract` Internal Cache Map in `findStorageBatch()`

## Summary
`ContractStateServiceImpl.findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` for every unique `contractId`. Because `cacheManagerSlotsPerContract` is a `CaffeineCacheManager` configured without `setCacheNames()` (dynamic mode), Spring's internal `cacheMap` grows without bound. Eviction from the outer `contractSlotsCache` does not remove entries from `cacheManagerSlotsPerContract.cacheMap`, so every unique contract ID ever seen permanently retains a `CaffeineCache` object in the JVM heap.

## Finding Description

**Exact code path — confirmed against source:**

`ContractStateServiceImpl.java` lines 85–87: every call to `findStorageBatch()` invokes the loader `() -> cacheManagerSlotsPerContract.getCache(contractId.toString())` for any `contractId` not already present in `contractSlotsCache`. [1](#0-0) 

`EvmConfiguration.java` lines 107–112: `cacheManagerSlotsPerContract` is the **only** `CaffeineCacheManager` bean in the file that does **not** call `setCacheNames()`. Every other bean (`cacheManagerContractSlots`, `cacheManagerContractState`, `cacheManagerEntity`, etc.) calls `setCacheNames(...)`, which puts the manager into static mode and prevents dynamic cache creation. The absence of `setCacheNames()` here is the root cause. [2](#0-1) 

**Cache size configuration — confirmed:**

- `contractSlots` (outer cache): `expireAfterAccess=5m, maximumSize=3000` — bounds active entries in `contractSlotsCache`, not entries in `cacheManagerSlotsPerContract.cacheMap`. [3](#0-2) 
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — this spec is applied to each individual `CaffeineCache` created inside `cacheManagerSlotsPerContract`, bounding the number of *slot keys per contract*, not the number of *contract caches* in the manager's internal map. [4](#0-3) 

**Root cause:**

Spring's `CaffeineCacheManager.getCache(name)` stores every created `CaffeineCache` in an internal `ConcurrentHashMap<String, Cache> cacheMap` with no eviction and no size bound. When `contractSlotsCache` evicts an entry for a given `contractId` (after 5 minutes of inactivity or when the 3000-entry limit is reached), the corresponding `CaffeineCache` object is removed from `contractSlotsCache`'s value set, but `cacheManagerSlotsPerContract.cacheMap` still holds a strong reference to it under the key `contractId.toString()`. The object is never garbage-collected. [2](#0-1) 

## Impact Explanation
Each retained `CaffeineCache` carries Caffeine's internal `BoundedLocalCache` structures (a `ConcurrentHashMap`, `MpscGrowableArrayQueue`, scheduler references, etc.), consuming on the order of 1–10 KB per instance. After `contractSlotsCache` cycles through its 3000-entry window, all previously evicted contract IDs remain permanently in `cacheManagerSlotsPerContract.cacheMap`. At sustained request rates, this leads to linear heap growth unbounded by any configured cache limit, eventually triggering `OutOfMemoryError` and crashing the web3 node process. [1](#0-0) 

## Likelihood Explanation
The attack requires only unauthenticated HTTP POST requests to `/api/v1/contracts/call` targeting distinct contract addresses. Contract addresses can be enumerated sequentially. The global rate limit is not per-source, so a single client can saturate it. The `enableBatchContractSlotCaching` flag defaults to `true`, meaning the vulnerable code path is active by default. [5](#0-4) 

## Recommendation
Call `setCacheNames()` on `cacheManagerSlotsPerContract` with a fixed set of names to put it into static mode, preventing dynamic cache creation. Alternatively, replace the two-level caching design with a single `CaffeineCache` keyed by `(contractId, slotKey)` pairs, eliminating the need for a dynamic per-contract cache manager entirely. If the two-level design is retained, add a `RemovalListener` on `contractSlotsCache` that explicitly calls an invalidation/removal method on `cacheManagerSlotsPerContract` when a contract entry is evicted. [2](#0-1) 

## Proof of Concept
```
# Send requests targeting N distinct contract addresses
for i in $(seq 1 100000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<host>/api/v1/contracts/call \
    -H "Content-Type: application/json" \
    -d "{\"data\":\"0x\",\"to\":\"$ADDR\",\"estimate\":false}" &
done
wait
```
Each unique address causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to be called once, creating and permanently retaining a new `CaffeineCache` in the manager's internal map. After `contractSlotsCache` evicts entries beyond its 3000-entry limit, the corresponding `CaffeineCache` objects in `cacheManagerSlotsPerContract.cacheMap` are never freed. JVM heap usage grows linearly with the number of unique addresses used. [6](#0-5)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-91)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
        final var wrappedKey = ByteBuffer.wrap(key);
        // Cached slot keys for contract, whose slot values are not present in the contractStateCache
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
        final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
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
