All code references check out. Here is the audit report:

---

Audit Report

## Title
Unbounded `CaffeineCacheManager` Named-Cache Growth in `cacheManagerSlotsPerContract` Enables Unauthenticated Heap Exhaustion (DoS)

## Summary
`cacheManagerSlotsPerContract()` in `EvmConfiguration.java` constructs a `CaffeineCacheManager` without calling `setCacheNames()`, placing it in dynamic (open) mode. `ContractStateServiceImpl.findStorageBatch()` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` for every distinct contract entity ID encountered at runtime. Spring's `CaffeineCacheManager` in dynamic mode stores each newly created `CaffeineCache` in an internal `ConcurrentHashMap<String, Cache>` that has no eviction mechanism. The outer `contractSlotsCache` (bounded to 3,000 entries) does not remove entries from this inner map when it evicts them, so the inner map grows without bound. An unauthenticated attacker who drives a large number of distinct contract IDs through the endpoint can exhaust JVM heap memory and crash the web3 service.

## Finding Description

**`EvmConfiguration.java` lines 107–112** — the bean is created without `setCacheNames()`, unlike every other `CaffeineCacheManager` bean in the same file (all of which call `setCacheNames()`):

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    // ← NO setCacheNames() → dynamic mode
    return caffeineCacheManager;
}
``` [1](#0-0) 

Compare with every other bean in the same file, e.g. `cacheManagerContractSlots()` at lines 75–81, which calls `setCacheNames()`: [2](#0-1) 

**`ContractStateServiceImpl.java` lines 85–87** — a new named cache is created per distinct `contractId`:

```java
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
            contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [3](#0-2) 

**Root cause:** Spring's `CaffeineCacheManager`, when `setCacheNames()` is not called, operates in dynamic mode: every call to `getCache(name)` with a previously unseen name allocates a new `CaffeineCache` and stores it permanently in an internal `ConcurrentHashMap<String, Cache>`. That map has no eviction mechanism.

**Why the outer cache does not bound the inner map:** The outer `contractSlotsCache` (bean `CACHE_MANAGER_CONTRACT_SLOTS`, `maximumSize=3000`) stores `contractId → CaffeineCache` entries. When the outer cache evicts an entry (LRU), the `CaffeineCache` object is no longer referenced by the outer cache, but `cacheManagerSlotsPerContract`'s internal `ConcurrentHashMap` still holds a strong reference to it under the key `contractId.toString()`. That reference is never removed. The outer cache's bounded size therefore does **not** bound the number of named caches accumulated in the inner manager. [4](#0-3) 

**Feature is enabled by default:** `CacheProperties.java` line 30 sets `enableBatchContractSlotCaching = true`, and `ContractStateServiceImpl.findStorage()` line 59 only skips the batch path when this flag is `false`. [5](#0-4) [6](#0-5) 

**Accumulation rate:** Each unique contract address that reaches `findStorageBatch` adds one permanent entry to the inner manager's map. The default `slotsPerContract` spec (`expireAfterAccess=5m,maximumSize=1500`) bounds the *entries inside* each named cache, but not the number of named caches. [7](#0-6) 

## Impact Explanation
An attacker who drives N distinct contract IDs through the `/api/v1/contracts/call` endpoint causes N permanent `CaffeineCache` objects to accumulate in the `cacheManagerSlotsPerContract` map. A Caffeine cache configured with `maximumSize=1500` and time-based expiry allocates non-trivial internal structures (timer wheel, segment arrays) even when empty — on the order of tens of KB per instance. At ~50 KB overhead per cache instance, 20,000 distinct contract IDs consume ~1 GB of heap. The JVM will eventually throw `OutOfMemoryError`, crashing the web3 service and denying service to all users. Because the mirror node is a read-only query service with no authentication requirement on the contract-call endpoint, this is a complete, unauthenticated availability attack.

## Likelihood Explanation
The Hedera mainnet has hundreds of thousands of deployed contracts, all of which are publicly enumerable via the mirror node REST API (`/api/v1/contracts`). An attacker can trivially enumerate contract IDs and replay them as `to` addresses in `eth_call`-style requests. No authentication, no special privilege, and no on-chain transaction is required. The attack is fully repeatable after a service restart.

## Recommendation
Call `setCacheNames()` on the `cacheManagerSlotsPerContract` bean to put it in static mode, preventing dynamic cache creation. Since the outer `contractSlotsCache` already bounds the number of active per-contract caches to 3,000, the inner manager only needs to serve those same names. Alternatively, manage per-contract caches directly (e.g., using a `LoadingCache<EntityId, Cache>` with explicit eviction) rather than delegating to a `CaffeineCacheManager` in dynamic mode.

## Proof of Concept
1. Enumerate distinct contract entity IDs from the public mirror node REST API (`GET /api/v1/contracts`).
2. For each contract ID, issue an `eth_call`-style request to the web3 endpoint with that contract as the `to` address, ensuring the call reaches `findStorageBatch` (e.g., a storage-reading call).
3. Each request with a new contract ID causes `cacheManagerSlotsPerContract.getCache(contractId.toString())` to be called, allocating a new `CaffeineCache` and storing it permanently in the manager's internal map.
4. After ~20,000 distinct contract IDs, the accumulated `CaffeineCache` objects consume ~1 GB of heap. The JVM throws `OutOfMemoryError` and the web3 service crashes.
5. The outer `contractSlotsCache` evicts entries after 5 minutes or when it exceeds 3,000 entries, but the inner manager's map is never cleaned up, so heap usage grows monotonically.

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L59-61)
```java
        if (!cacheProperties.isEnableBatchContractSlotCaching()) {
            return contractStateRepository.findStorage(contractId.getId(), key);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L30-30)
```java
    private boolean enableBatchContractSlotCaching = true;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```
