The code references in the claim are accurate. Let me verify the critical facts before rendering a verdict:

**Verified facts:**

1. `cacheManagerSlotsPerContract()` at lines 107–112 of `EvmConfiguration.java` does **not** call `setCacheNames()`, leaving the manager in dynamic mode. [1](#0-0) 

2. Every other `CaffeineCacheManager` bean in the same file calls `setCacheNames()` — this omission is unique to `cacheManagerSlotsPerContract`. [2](#0-1) 

3. `findStorageBatch` calls `cacheManagerSlotsPerContract.getCache(contractId.toString())` on every outer-cache miss, registering a new named cache in the manager's internal `cacheMap` for each unique contract ID. [3](#0-2) 

4. The outer `contractSlots` cache is bounded at `maximumSize=3000`; the inner `slotsPerContract` spec is `expireAfterAccess=5m,maximumSize=1500`. [4](#0-3) 

5. Spring's `CaffeineCacheManager` in dynamic mode stores every created `CaffeineCache` in a `ConcurrentHashMap<String, Cache> cacheMap` with no removal callback. Eviction from the outer Caffeine cache removes the value from that cache's table but has no hook into `CaffeineCacheManager.cacheMap`, so the reference is never released.

All line references, the root cause, the exploit path, and the configuration values are confirmed correct.

---

# Audit Report

## Title
Unbounded `CaffeineCacheManager` Internal Registry Growth via Unprivileged `eth_call` Requests

## Summary
`cacheManagerSlotsPerContract()` instantiates a `CaffeineCacheManager` in dynamic mode (no `setCacheNames()` call). Every unique contract ID passed to `getCache()` permanently inserts a new `CaffeineCache` into the manager's internal `ConcurrentHashMap<String, Cache> cacheMap`. The outer `contractSlots` Caffeine cache (maximumSize=3000) evicts its entries but has no eviction listener that removes the corresponding entries from `cacheMap`, so `cacheMap` grows monotonically. Any unauthenticated caller of the public `eth_call` / `estimateGas` endpoint can drive this growth without limit.

## Finding Description

**`EvmConfiguration.java` lines 107–112** — `cacheManagerSlotsPerContract()` omits `setCacheNames()`:

```java
@Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
CaffeineCacheManager cacheManagerSlotsPerContract() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
    return caffeineCacheManager;
}
``` [1](#0-0) 

Every other `CaffeineCacheManager` bean in the same class calls `setCacheNames()` to fix the set of known caches. This one does not. [2](#0-1) 

**`ContractStateServiceImpl.java` lines 85–87** — on every outer-cache miss the loader calls `cacheManagerSlotsPerContract.getCache(contractId.toString())`:

```java
final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
        contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
``` [3](#0-2) 

In dynamic mode, `CaffeineCacheManager.getCache(name)` creates a new `CaffeineCache` and inserts it into `cacheMap` if the name is unseen. There is no removal path: `cacheMap` is a plain `ConcurrentHashMap` with no size bound and no eviction listener wired to the outer Caffeine cache.

**Root cause / failed assumption:** The design assumes the outer `contractSlots` cache (maximumSize=3000) bounds memory by evicting `CaffeineCache` values when capacity is exceeded. This assumption is wrong. Caffeine eviction removes the entry from the outer cache's internal table but does not call back into `CaffeineCacheManager` to remove the corresponding entry from `cacheMap`. The `cacheMap` therefore accumulates a strong reference to every `CaffeineCache` ever created and never releases any of them.

The `maximumSize=1500` in `slotsPerContract = "expireAfterAccess=5m,maximumSize=1500"` limits the number of slot keys stored inside each individual per-contract cache, not the number of per-contract cache objects registered in `cacheMap`. [5](#0-4) 

## Impact Explanation
Each `CaffeineCache` object wraps a full Caffeine cache instance (internal `BoundedLocalCache` with timer wheel, write buffer, maintenance executor reference, and statistics objects). At the default 500 RPS rate limit, an attacker can register approximately 500 new contract caches per second (one per unique contract ID). After sustained attack the `cacheMap` holds millions of live `CaffeineCache` objects, none of which are eligible for GC. This causes progressive heap exhaustion, eventually triggering `OutOfMemoryError` and crashing the web3 service — a complete denial of service. Even at lower rates the growing `cacheMap` increases GC pressure and degrades response latency.

## Likelihood Explanation
The `eth_call` and `estimateGas` endpoints are public and require no authentication. Hedera contract addresses are sequential entity IDs, making enumeration of valid contract IDs trivial. The attack requires only HTTP POST requests to the mirror node's web3 API and can be fully automated. The 500 RPS rate limit (`hiero.mirror.web3.throttle.requestsPerSecond=500`) does not prevent the attack; it only determines the rate at which the heap fills. [6](#0-5) 

## Recommendation

1. **Fix the dynamic-mode leak** — call `setCacheNames()` with a fixed set of names on `cacheManagerSlotsPerContract`, or replace the per-contract `CaffeineCacheManager` pattern with a single bounded `ConcurrentHashMap<EntityId, CaffeineCache>` whose size is explicitly capped (e.g., at 3000, matching the outer cache).

2. **Wire an eviction listener** — if the dynamic-manager pattern must be kept, register a Caffeine `removalListener` on the outer `contractSlots` cache that calls a custom cleanup method to remove the evicted contract's entry from `cacheMap`.

3. **Align the two bounds** — ensure the number of named caches that can ever exist in `cacheMap` is bounded by the same `maximumSize` as the outer `contractSlots` cache (3000), so eviction from the outer cache is always matched by removal from `cacheMap`.

## Proof of Concept

```
# Send eth_call requests targeting N distinct contract entity IDs
# Each request causes cacheManagerSlotsPerContract.getCache("<id>") to register
# a new CaffeineCache in cacheMap, which is never removed.

for i in $(seq 1 100000); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"0x\",\"to\":\"0x$(printf '%040x' $i)\",\"gas\":30000}" &
done
wait

# After the outer contractSlots cache fills (3000 entries) and begins evicting,
# cacheMap continues to grow. Heap usage increases monotonically.
# Monitor with: jmap -histo <pid> | grep CaffeineCache
```

After the outer cache reaches its 3000-entry limit and starts evicting, `cacheMap` in `CaffeineCacheManager` retains all previously created `CaffeineCache` instances. Heap profiling will show an ever-growing count of `CaffeineCache` / `BoundedLocalCache` objects correlated with the number of unique contract IDs seen, confirming the unbounded registry growth.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L67-105)
```java
    @Bean(CACHE_MANAGER_CONTRACT)
    CacheManager cacheManagerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
        return caffeineCacheManager;
    }

    @Bean(CACHE_MANAGER_CONTRACT_SLOTS)
    CacheManager cacheManagerContractSlots() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCacheNames(Set.of(CACHE_NAME));
        cacheManager.setCacheSpecification(cacheProperties.getContractSlots());
        return cacheManager;
    }

    @Bean(CACHE_MANAGER_CONTRACT_STATE)
    CacheManager cacheManagerContractState() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContractState());
        return caffeineCacheManager;
    }

    @Bean(CACHE_MANAGER_SYSTEM_ACCOUNT)
    CacheManager cacheManagerSystemAccount() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getSystemAccount());
        return caffeineCacheManager;
    }

    @Bean(CACHE_MANAGER_ENTITY)
    CacheManager cacheManagerEntity() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME, CACHE_NAME_EVM_ADDRESS, CACHE_NAME_ALIAS));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getEntity());
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-87)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-39)
```java
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
