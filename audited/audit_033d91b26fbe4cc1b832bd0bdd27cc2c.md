### Title
Permanent Stale Long-Zero Address Caching in `SyntheticLogListener.updateTopicField()` Due to No-TTL Caffeine Cache

### Summary
`SyntheticLogListener.updateTopicField()` explicitly caches the `defaultValue` (long-zero address) into the `evmCache` when no EVM address is found for an entity. Because the `evmCache` is configured with `maximumSize=500000,recordStats` — **no expiry** — this cached long-zero address persists for the lifetime of the importer process. If the entity later acquires a real EVM address (e.g., via `CRYPTO_UPDATE` adding an ECDSA key), all subsequent synthetic log topics referencing that entity will permanently serve the stale long-zero address, corrupting the EVM-compatible view of HTS transfer history.

### Finding Description

**Exact code path:**

`CacheProperties.java` line 24 — the `evmCache` has no TTL:
```
private String evmAddress = "maximumSize=500000,recordStats";
```

`SyntheticLogListener.java` lines 225–231 — the fallback unconditionally writes the long-zero address into the permanent cache:
```java
} else {
    /* The entity repository only returns rows that have a non-empty evm address
    and the entity was not created in this block so we can safely assume the
    entity does not have an evm address. ... */
    getEvmCache().put(key.getId(), defaultValue);
}
```

`EntityRepository.java` line 22–23 — the DB query only returns entities that already have an EVM address:
```sql
select evm_address,id from entity where id in (?1) and length(evm_address) > 0
```

**Root cause:** The comment at line 226–229 encodes a false assumption: *"we can safely assume the entity does not have an evm address"*. This is only true at the moment of processing. Hedera accounts can acquire EVM addresses after creation (e.g., via `CRYPTO_UPDATE` with an ECDSA key). Once the long-zero address is written into the no-TTL Caffeine `LoadingCache`, Caffeine's `getAll()` will never call `loadAll()` for that key again, so the DB is never re-queried.

**Exploit flow:**
1. Attacker creates account `0.0.N` with an ED25519 key (no EVM address).
2. Attacker (or anyone) performs an HTS token transfer involving `0.0.N`, generating a synthetic `Transfer` log with topic1/topic2 = long-zero address of `N`.
3. Importer processes the record file: `findEvmAddressesByIds` returns no row for `N` (filtered by `length(evm_address) > 0`); `parserContext.get(Entity.class, N)` returns null (entity not in current block). Fallback fires: `getEvmCache().put(N, defaultValue)` — long-zero address `0x000...N` is permanently cached.
4. Attacker submits `CRYPTO_UPDATE` for `0.0.N` adding an ECDSA key, giving it a real EVM address `0xABCD...`.
5. All future synthetic logs referencing `0.0.N` hit the cache at line 216 (`entityEvmAddresses.get(key.getId())`) and receive the stale long-zero address. The DB is never re-queried.

**Why existing checks fail:**
- The `parserContext` check (lines 220–224) only covers entities created/modified in the *current* record file. Cross-file updates are invisible to it.
- There is no `onStart()` or cache invalidation hook anywhere in `SyntheticLogListener`.
- The test `cachesNoDbResults` (unit test lines 96–120) explicitly validates and locks in this broken behavior — confirming it is intentional but incorrectly assumed safe.

### Impact Explanation
Synthetic contract logs are the EVM-compatible representation of HTS token transfers, consumed by `eth_getLogs` and EVM indexers. Corrupted `topic1`/`topic2` fields mean Transfer events show the wrong sender/receiver EVM address. DeFi protocols, wallets, and block explorers relying on these events will misattribute token movements. The bloom filter (`contractLog.setBloom`) is also computed from the stale address (line 160), causing false negatives in log filtering. This constitutes permanent, silent corruption of historical synthetic log data for any entity that transitions from no-EVM-address to having one.

### Likelihood Explanation
Any unprivileged Hedera user can execute this in three self-controlled steps: create an ED25519 account, perform one HTS transfer, then update the account with an ECDSA key. No special permissions, no admin access, no race condition exploitation is required. The window is not time-bounded — the cache entry persists until the importer process restarts. On mainnet, where the importer runs continuously for months, the stale entry can corrupt logs indefinitely. The attack is repeatable for any number of entity IDs up to the cache's 500,000-entry limit.

### Recommendation
1. **Remove the unconditional negative caching**: Do not call `getEvmCache().put(key.getId(), defaultValue)` in the fallback branch. Instead, leave the key absent from the cache so it is re-queried on the next record file.
2. **Add a TTL**: Change the cache spec to include `expireAfterWrite=Xm` (e.g., 30 minutes) so stale entries are eventually evicted even if negative caching is retained for performance.
3. **Invalidate on entity update**: In the `EntityListener.onEntity()` callback, if the entity has a non-empty EVM address, call `getEvmCache().invalidate(entity.getId())` to force a fresh lookup.
4. **Fix the false assumption in the comment**: The comment "we can safely assume the entity does not have an evm address" is incorrect for long-lived caches spanning multiple record files.

### Proof of Concept
```
1. Submit CRYPTO_CREATE with ED25519 key → account 0.0.N created, evm_address = NULL in DB.

2. Submit HTS TokenTransfer: token T, from 0.0.N to 0.0.M.
   → Importer generates synthetic Transfer log with topic1 = long-zero(N).
   → onEnd() fires: findEvmAddressesByIds({N, M, contractId}) returns no row for N.
   → updateTopicField() fallback: evmCache.put(N, long-zero(N)).  ← POISON ENTRY

3. Submit CRYPTO_UPDATE for 0.0.N adding ECDSA key with public key P.
   → Importer sets entity.evm_address = keccak256(P)[12:] = 0xABCD... in DB.

4. Submit another HTS TokenTransfer: token T, from 0.0.N to 0.0.M.
   → Importer generates synthetic Transfer log with topic1 = long-zero(N).
   → onEnd() fires: getEvmCache().getAll({N, M, contractId}).
   → Caffeine returns cached long-zero(N) for key N — DB NOT queried.
   → updateTopicField(): cachedResult = long-zero(N) ≠ null → setter.accept(long-zero(N)).
   → Persisted contract_log.topic1 = long-zero(N) instead of 0xABCD...

5. Query eth_getLogs for token T Transfer events:
   → topic1 = 0x000...N (wrong) instead of 0xABCD... (correct).
   → EVM clients attribute the transfer to the long-zero address, not the real EVM address.
```