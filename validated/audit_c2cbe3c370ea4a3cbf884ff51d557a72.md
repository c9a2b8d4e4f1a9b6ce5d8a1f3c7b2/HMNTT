All code references check out. Let me verify the exact behavior before rendering a verdict.

**Verified facts:**

- `EvmConfiguration.java` lines 107–112: `cacheManagerSlotsPerContract()` creates a `CaffeineCacheManager` with only `setCacheSpecification()` — no `setCacheNames()` call, confirmed. Every other bean in the same file calls `setCacheNames()`. [1](#0-0) 

- `ContractStateServiceImpl.java` line 87: `cacheManagerSlotsPerContract.getCache(contractId.toString())` is called as a value loader inside `this.contractSlotsCache.get(contractId, ...)`. [2](#0-1) 

- `contractSlots` is configured `expireAfterAccess=5m,maximumSize=3000` — this bounds the outer cache, not the inner `cacheMap`. [3](#0-2) 

- `slotsPerContract` spec is `expireAfterAccess=5m,maximumSize=1500` — this is applied to each individual named `CaffeineCache`, not to the `cacheMap` that holds them. [4](#0-3) 

- SECURITY.md excludes "Impacts that only require DDoS" and "Best practice recommendations." This finding is neither — it is a specific code defect (omitted `setCacheNames()`) causing unbounded heap growth, distinct from volumetric DDoS. [5](#0-4) 

---

# Audit Report

## Title
Unbounded `CaffeineCacheManager` Internal Map Growth via Dynamic Cache Creation in `cacheManagerSlotsPerContract` Leads to JVM Heap Exhaustion

## Summary
`cacheManagerSlotsPerContract()` omits `setCacheNames()`, leaving Spring's `CaffeineCacheManager` in dynamic mode. Every unique `contractId` ever queried permanently inserts a new named `CaffeineCache` into the manager's internal `ConcurrentHashMap<String, Cache> cacheMap`. This map is never pruned — even when the outer `contractSlotsCache` evicts entries — allowing an unprivileged attacker to exhaust JVM heap by issuing requests against a large number of distinct contract addresses.

## Finding Description

**Root cause — `EvmConfiguration.java` lines 107–112:**

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;   // dynamic=true; cacheMap is unbounded
}
``` [1](#0-0) 

Every other `CaffeineCacheManager` bean in the same file calls `setCacheNames()`, which sets `dynamic = false` and prevents new names from being registered at runtime. This bean does not. [6](#0-5) 

**Trigger path — `ContractStateServiceImpl.java` line 87:**

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [2](#0-1) 

On every cache miss for `contractId` in the outer `contractSlotsCache`, Spring's `CaffeineCacheManager.getCache(name)` is invoked with a new name. Internally, Spring checks its `cacheMap`; if the name is absent and `dynamic == true`, it creates a new `CaffeineCache` and inserts it permanently into `cacheMap`.

**Why the outer bound does not help:**

`contractSlotsCache` is configured `expireAfterAccess=5m, maximumSize=3000`. [3](#0-2) 

When an entry is evicted from `contractSlotsCache`, the `CaffeineCache` value is no longer referenced by the outer cache — but it remains referenced by `cacheManagerSlotsPerContract.cacheMap`. The `cacheMap` is a plain `ConcurrentHashMap` with no eviction, expiry, or size cap. It accumulates one entry per unique `contractId` ever seen, growing monotonically for the lifetime of the JVM.

Each entry in `cacheMap` is a `CaffeineCache` wrapping a Caffeine cache configured with `expireAfterAccess=5m, maximumSize=1500`. Even when empty, each Caffeine cache instance allocates internal data structures (scheduler references, policy arrays, etc.), consuming non-trivial heap per instance.

## Impact Explanation
The web3 service becomes unavailable as JVM heap is exhausted, causing `OutOfMemoryError` or severe GC thrashing. All `eth_call`, `eth_sendRawTransaction`, and balance-query operations fail. The attack is immediately repeatable after each service restart because the `cacheMap` starts empty again and the same exploit path is available from the first request.

## Likelihood Explanation
No authentication is required — any caller of the public JSON-RPC endpoint can trigger this. The outer cache's `maximumSize=3000` does not prevent the attack; it only means the attacker must use more than 3000 unique contract addresses to begin accumulating entries beyond what the outer cache would naturally hold. Ethereum address space is 2^160, so generating millions of distinct addresses is trivial. Rate limiting slows but does not prevent the attack.

## Recommendation

Call `setCacheNames()` on the `cacheManagerSlotsPerContract` bean to disable dynamic mode. Because the cache names are dynamic (one per `contractId`), the correct fix is to restructure the caching design: instead of creating one named cache per contract inside a `CaffeineCacheManager`, use a single named cache with a composite key `(contractId, slotKey)`, consistent with how `contractStateCache` works. Alternatively, if the per-contract sub-cache design is intentional, replace `CaffeineCacheManager` with a manually managed `ConcurrentHashMap` that is itself size-bounded and eviction-aware (e.g., a Caffeine cache of Caffeine caches).

## Proof of Concept

1. Start the web3 service with default heap settings.
2. In a loop, send `eth_call` JSON-RPC requests each targeting a distinct contract address (e.g., sequentially incrementing addresses `0x0000...0001`, `0x0000...0002`, …).
3. Each request that misses `contractSlotsCache` invokes `cacheManagerSlotsPerContract.getCache(contractId.toString())`, inserting a new entry into `cacheMap`.
4. After ~3000 requests, `contractSlotsCache` begins evicting old entries, but `cacheMap` retains all of them.
5. Continue until `cacheMap` size × per-entry heap overhead exceeds available heap → `OutOfMemoryError` → service crash.
6. Restart the service and repeat immediately.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L67-73)
```java
    @Bean(CACHE_MANAGER_CONTRACT)
    CacheManager cacheManagerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
        return caffeineCacheManager;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L86-87)
```java
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-25)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
