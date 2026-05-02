I have verified all code references against the actual repository. Here is my assessment:

**Verification of all claims:**

- `updateTopicField()` at lines 210–235: confirmed. [1](#0-0) 
- `getEvmCache().put(key.getId(), defaultValue)` at line 231 (no setter call in else branch): confirmed. [2](#0-1) 
- Cache built with `"maximumSize=500000,recordStats"` — no TTL: confirmed. [3](#0-2) 
- `getEvmCache().getAll(keys)` at line 70: confirmed. [4](#0-3) 
- `findEvmAddressesByIds` query at line 22: confirmed. [5](#0-4) 
- `parserContext.get(Entity.class, key.getId())` check at line 220: confirmed. [6](#0-5) 

All line references, logic, and behavioral claims are accurate. The vulnerability is real.

---

# Audit Report

## Title
Permanent EVM Address Cache Poisoning via No-Expiry `evmCache` in `SyntheticLogUpdater.updateTopicField()`

## Summary
`SyntheticLogListener.SyntheticLogUpdater.updateTopicField()` unconditionally writes a long-zero address into the singleton `evmCache` for any entity that currently lacks an EVM alias. Because the `evmCache` is configured with `maximumSize=500000,recordStats` — **no TTL** — this stale entry is never refreshed. Any subsequent `onEnd()` call for a later stream file returns the cached stale long-zero address via `getEvmCache().getAll(keys)`, permanently suppressing the entity's real EVM alias in all future synthetic contract log topics.

## Finding Description

**Exact code path:**

In `SyntheticLogListener.java`, `onEnd()` calls `getEvmCache().getAll(keys)` to resolve EVM addresses for all entities referenced in the current stream file:

```java
final var entityMap = getEvmCache().getAll(keys);  // line 70
``` [7](#0-6) 

For a Caffeine `LoadingCache`, `getAll()` invokes the `CacheLoader` only for keys **absent** from the cache. Keys already present are returned directly from cache without any DB query.

`updateTopicField()` then processes the result:

```java
var cachedResult = entityEvmAddresses.get(key.getId());
if (cachedResult != null) {
    setter.accept(cachedResult);          // uses cached value — no DB re-check
} else {
    var contextEntity = parserContext.get(Entity.class, key.getId());
    if (contextEntity != null && !ArrayUtils.isEmpty(contextEntity.getEvmAddress())) {
        ...
    } else {
        getEvmCache().put(key.getId(), defaultValue);  // line 231: caches long-zero address
        // NOTE: setter is NOT called here — topic retains its original value
    }
}
``` [8](#0-7) 

When the entity has no EVM alias, `defaultValue` is `contractLog.getTopic1()` or `contractLog.getTopic2()` — the raw long-zero address bytes already in the log. The else branch caches this long-zero address but does not call `setter`, so the current stream file is processed correctly. However, the cache is now poisoned for all future stream files.

**Root cause — failed assumption:**

The inline comment at lines 226–230 states: *"we can safely assume the entity does not have an evm address."* This assumption is only valid at the instant of processing. The `evmCache` is built with:

```java
Caffeine.from(CaffeineSpec.parse(cacheProperties.getEvmAddress()))
``` [9](#0-8) 

where `cacheProperties.getEvmAddress()` returns `"maximumSize=500000,recordStats"` — no `expireAfterWrite`, no `expireAfterAccess`: [10](#0-9) 

Entries live until LRU eviction at 500,000 entries or JVM restart. There is no cache invalidation path anywhere in the codebase for `evmCache` entries.

**`findEvmAddressesByIds` is never re-queried after a cache write:**

```sql
select evm_address,id from entity where id in (?1) and length(evm_address) > 0
``` [5](#0-4) 

This query is only reached on a cache miss. After the first cache write for entity ID `N`, it is never called for `N` again.

**Why the `parserContext` check is insufficient:**

The `parserContext.get(Entity.class, key.getId())` check at line 220 only covers entities created or updated *within the same stream file*. It provides no protection for entities that acquired an alias in a prior stream file. [6](#0-5) 

## Impact Explanation

All synthetic HTS transfer contract logs for any account that was first seen without an EVM alias will permanently display the wrong `topic1`/`topic2` value (long-zero address instead of the real EVM alias) after the account acquires an alias. The bloom filter computed at lines 159–161 is also incorrect because it is built from the (already-corrupted) topic values: [11](#0-10) 

The corruption is persistent — it survives across stream files until the cache entry is evicted by size pressure (at 500,000 entries) or the JVM restarts. EVM-based applications (wallets, indexers, DeFi protocols) that subscribe to `Transfer(address,address,uint256)` events and filter by the alias address will silently miss these events.

## Likelihood Explanation

The precondition (account without alias later acquiring one) is a standard Hedera account lifecycle: accounts created via `CryptoCreate` without an alias, then later used with an ECDSA key or updated via `CryptoUpdate`. The trigger (any HTS transfer involving that account before the alias is set) requires no special privilege — any network participant can send tokens to any account. The window between account creation and alias assignment can be arbitrarily long, making the race trivially achievable. The bug is deterministic and repeatable.

## Recommendation

1. **Add a TTL to the `evmCache`**: Change the cache spec from `"maximumSize=500000,recordStats"` to include `expireAfterWrite=<duration>` (e.g., `expireAfterWrite=1h`). This bounds the staleness window.

2. **Do not cache negative results (long-zero addresses) as definitive**: In the else branch of `updateTopicField()`, avoid writing the long-zero address into the cache. Only cache confirmed EVM aliases (non-null, non-empty values returned from the DB or `parserContext`). This prevents the cache from ever blocking a future DB lookup for an entity that had no alias at the time of first processing.

3. **Invalidate on alias assignment**: When an entity's EVM alias is set or updated (e.g., during `CryptoUpdate` processing), explicitly invalidate the corresponding `evmCache` entry.

## Proof of Concept

1. Account A (entity ID `N`) is created via `CryptoCreate` with no alias. Long-zero address: `0x000…000N`.
2. Any participant sends an HTS token transfer to/from account A.
3. Mirror node processes the stream file: `onContractLog()` creates a `SyntheticLogUpdater` with `sender = EntityId(N)`.
4. `onEnd()` → `getEvmCache().getAll({N})` → cache miss → DB returns nothing (no EVM address) → `entityEvmAddresses` is empty for `N`.
5. `updateTopicField()` falls into the else branch → `getEvmCache().put(N, 0x000…000N)`. Cache is now poisoned.
6. Account A acquires EVM alias `0xABCD…` (e.g., via `CryptoUpdate` or first ECDSA-key transaction in a subsequent stream file).
7. A new HTS transfer involving account A arrives in a later stream file.
8. `onEnd()` → `getEvmCache().getAll({N})` → **cache HIT** → returns stale `0x000…000N`.
9. `updateTopicField()` sees `cachedResult != null` → calls `setter.accept(0x000…000N)` → `contractLog.setTopic1(0x000…000N)`.
10. The bloom filter is computed with the wrong address.
11. The incorrect data is persisted to the database and served to all consumers indefinitely.

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L68-74)
```java
        final var logUpdaters = parserContext.getTransient(SyntheticLogUpdater.class);
        final var keys = parserContext.getEvmAddressLookupIds();
        final var entityMap = getEvmCache().getAll(keys);

        for (var updater : logUpdaters) {
            updater.updateContractLog(entityMap);
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L91-103)
```java
    private LoadingCache<Long, byte[]> buildCache() {
        return Caffeine.from(CaffeineSpec.parse(cacheProperties.getEvmAddress()))
                .build(new CacheLoader<>() {
                    @Override
                    public byte[] load(Long key) {
                        return loadAll(Collections.singleton(key)).get(key);
                    }

                    @Override
                    public Map<Long, byte[]> loadAll(Set<? extends Long> keys) {
                        return getCacheMisses(keys);
                    }
                });
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L158-161)
```java
            var contractAddress = getContractAddress(contractId, entityEvmAddresses);
            if (Arrays.equals(CONTRACT_LOG_MARKER, contractLog.getBloom())) {
                contractLog.setBloom(createBloom(contractAddress));
            }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L210-235)
```java
        public void updateTopicField(
                final EntityId key,
                final Map<Long, byte[]> entityEvmAddresses,
                final Consumer<byte[]> setter,
                final byte[] defaultValue) {
            if (!EntityId.isEmpty(key)) {
                var cachedResult = entityEvmAddresses.get(key.getId());
                if (cachedResult != null) {
                    setter.accept(cachedResult);
                } else {
                    var contextEntity = parserContext.get(Entity.class, key.getId());
                    if (contextEntity != null && !ArrayUtils.isEmpty(contextEntity.getEvmAddress())) {
                        var trimmedEvmAddress = trim(contextEntity.getEvmAddress());
                        getEvmCache().put(key.getId(), trimmedEvmAddress);
                        setter.accept(trimmedEvmAddress);
                    } else {
                        /* The entity repository only returns rows that have a non-empty evm address
                        and the entity was not created in this block so we can safely assume the
                        entity does not have an evm address. In addition, we know the default value here
                        will be non-null as the key is derived from this value and is checked to be non-empty
                        */
                        getEvmCache().put(key.getId(), defaultValue);
                    }
                }
            }
        }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/config/CacheProperties.java (L23-24)
```java
    @NotBlank
    private String evmAddress = "maximumSize=500000,recordStats";
```

**File:** importer/src/main/java/org/hiero/mirror/importer/repository/EntityRepository.java (L22-23)
```java
    @Query(value = "select evm_address,id from entity where id in (?1) and length(evm_address) > 0", nativeQuery = true)
    List<EvmAddressMapping> findEvmAddressesByIds(Iterable<? extends Long> ids);
```
