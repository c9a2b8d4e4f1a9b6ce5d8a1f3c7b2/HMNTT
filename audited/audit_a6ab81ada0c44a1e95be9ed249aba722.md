### Title
Permanent EVM Address Cache Poisoning via No-Expiry `evmCache` in `SyntheticLogUpdater.updateTopicField()`

### Summary
`SyntheticLogListener.SyntheticLogUpdater.updateTopicField()` unconditionally writes the raw topic bytes (long-zero address) into the singleton `evmCache` for any entity that currently lacks an EVM alias. Because the `evmCache` is configured with `maximumSize=500000,recordStats` — **no TTL** — this stale long-zero address entry is never refreshed. Any subsequent `onEnd()` call for a later stream file returns the cached stale value via `getEvmCache().getAll(keys)`, permanently overriding the entity's real EVM alias in all future synthetic contract logs.

### Finding Description

**Exact code path:**

`SyntheticLogListener.java` lines 210–235 (`updateTopicField`):

```java
} else {
    // "safely assume the entity does not have an evm address"
    getEvmCache().put(key.getId(), defaultValue);   // line 231
}
```

`defaultValue` is `contractLog.getTopic1()` / `contractLog.getTopic2()` — the raw long-zero address bytes for the entity at the time of processing.

**Root cause — failed assumption:**

The inline comment at line 226–230 states: *"we can safely assume the entity does not have an evm address."* This is only true at the instant of processing. The `evmCache` is built at line 92 with:

```java
Caffeine.from(CaffeineSpec.parse(cacheProperties.getEvmAddress()))
```

where `cacheProperties.getEvmAddress()` returns `"maximumSize=500000,recordStats"` (no `expireAfterWrite`, no `expireAfterAccess`). Entries live until LRU eviction at 500 000 entries or JVM restart.

**`getEvmCache().getAll(keys)` (line 70) only invokes the `CacheLoader` for keys absent from the cache.** Once a long-zero address is written for entity ID `X`, every future `onEnd()` call returns that stale value for `X` without ever querying the DB again.

**`findEvmAddressesByIds` query** (line 22 of `EntityRepository.java`):

```sql
select evm_address,id from entity where id in (?1) and length(evm_address) > 0
```

This query is only reached on a cache miss. After the first cache write it is never called for that entity again.

**Exploit flow:**

1. Account A (entity ID `N`) exists with no EVM alias; its long-zero address is `0x000…000N`.
2. Attacker submits any HTS token transfer from/to account A (unprivileged, normal user action).
3. Mirror node processes the stream file: `onContractLog()` creates a `SyntheticLogUpdater` with `sender = EntityId(N)`.
4. `onEnd()` → `getEvmCache().getAll({N})` → cache miss → DB returns nothing (no EVM address) → `entityEvmAddresses` is empty for `N`.
5. `updateTopicField()` falls into the `else` branch → `getEvmCache().put(N, 0x000…000N)`.
6. Account A later acquires an EVM alias `0xABCD…` (e.g., via `CryptoUpdate` or first ECDSA-key transaction).
7. A subsequent HTS transfer involving account A arrives in a new stream file.
8. `onEnd()` → `getEvmCache().getAll({N})` → **cache HIT** → returns stale `0x000…000N`.
9. `updateTopicField()` calls `setter.accept(0x000…000N)` → `contractLog.setTopic1(0x000…000N)`.
10. The bloom filter is also computed with the wrong address (line 159–161).
11. The incorrect data is persisted to the database and served to all consumers.

**Why existing checks are insufficient:**

- The `parserContext.get(Entity.class, key.getId())` check (line 220) only covers entities created *within the same stream file*. It does not help for entities that acquired an alias in a prior stream file.
- There is no cache invalidation path anywhere in the codebase for `evmCache` entries.
- The `LoadingCache` contract guarantees the loader is skipped for already-present keys, so the DB is never re-queried.

### Impact Explanation
All synthetic HTS transfer contract logs for any account that was first seen without an EVM alias will permanently display the wrong `topic1`/`topic2` EVM address (long-zero instead of alias) after the account acquires an alias. The bloom filter stored alongside each log is also incorrect. EVM-based applications (wallets, indexers, DeFi protocols) that subscribe to `Transfer(address,address,uint256)` events and filter by the alias address will silently miss these events. The corruption is persistent — it survives across stream files until the cache entry is evicted by size pressure or the JVM restarts.

### Likelihood Explanation
The precondition (account without alias later acquiring one) is a standard Hedera lifecycle: accounts created via `CryptoCreate` without an alias, then later used with an ECDSA key or updated via `CryptoUpdate`. The trigger (any HTS transfer involving that account before the alias is set) requires no special privilege — any network participant can send tokens to any account. The window between account creation and alias assignment can be arbitrarily long, making the race trivially winnable. The bug is deterministic and repeatable.

### Recommendation
1. **Add a TTL to `evmCache`**: Change the spec to `maximumSize=500000,expireAfterWrite=<reasonable_duration>,recordStats` so stale long-zero entries are eventually refreshed.
2. **Do not cache negative results unconditionally**: In the `else` branch of `updateTopicField()` (line 225–232), avoid writing to `evmCache` when the entity has no EVM address, or use a separate short-lived negative cache.
3. **Invalidate on alias assignment**: When a `CryptoUpdate` or equivalent transaction sets an EVM alias on an entity, explicitly call `getEvmCache().invalidate(entityId)`.

### Proof of Concept

```
1. Create account A (0.0.12345) via CryptoCreate with no alias.
2. Submit CryptoTransfer: send 1 HBAR to account A.
   → Mirror node processes stream file S1.
   → Synthetic log generated: topic1 = 0x000...0000000000003039 (long-zero for 12345).
   → updateTopicField() caches 0x000...0000000000003039 for key 12345 in evmCache.
3. Submit CryptoUpdate for account A, setting evmAddress = 0xABCDEF...
   → Mirror node processes stream file S2.
   → entity table now has evm_address = 0xABCDEF... for id=12345.
4. Submit another HTS token transfer involving account A.
   → Mirror node processes stream file S3.
   → onEnd() calls getEvmCache().getAll({12345}).
   → Cache HIT: returns 0x000...0000000000003039 (stale).
   → Synthetic log topic1 is set to 0x000...0000000000003039 instead of 0xABCDEF...
   → DB query findEvmAddressesByIds is never called for key 12345.
5. Query the mirror node REST API for contract logs for account A by EVM address 0xABCDEF...
   → Transfer event from step 4 is NOT returned (wrong address in topic1).
   → Data corruption is permanent until cache eviction or restart.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L49-50)
```java
    @Getter(lazy = true)
    private final LoadingCache<Long, byte[]> evmCache = buildCache();
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L64-75)
```java
    public void onEnd(RecordFile recordFile) {
        if (!isEnabled()) {
            return;
        }
        final var logUpdaters = parserContext.getTransient(SyntheticLogUpdater.class);
        final var keys = parserContext.getEvmAddressLookupIds();
        final var entityMap = getEvmCache().getAll(keys);

        for (var updater : logUpdaters) {
            updater.updateContractLog(entityMap);
        }
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/contractlog/SyntheticLogListener.java (L225-232)
```java
                    } else {
                        /* The entity repository only returns rows that have a non-empty evm address
                        and the entity was not created in this block so we can safely assume the
                        entity does not have an evm address. In addition, we know the default value here
                        will be non-null as the key is derived from this value and is checked to be non-empty
                        */
                        getEvmCache().put(key.getId(), defaultValue);
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
