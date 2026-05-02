### Title
Cache Key Hash Collision in `findByEvmAddressOrAliasAndDeletedIsFalse` Enables Cross-User Entity Impersonation via 32-bit `Arrays.hashCode`

### Summary
The `CACHE_NAME_ALIAS` cache in `EntityRepository.findByEvmAddressOrAliasAndDeletedIsFalse` uses `@spelHelper.hashCode(#alias)` — which resolves to `Arrays.hashCode(byte[])`, a 32-bit polynomial hash — as the sole cache key. Because the 32-bit hash space is trivially collisible (birthday attack: ~65,536 attempts), an unprivileged attacker can craft a byte array that hashes identically to a victim's EVM address or alias, causing the shared Caffeine cache to return the victim's `Entity` object for the attacker's lookup. No secondary equality check on the actual byte array is performed after a cache hit.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode` delegates directly to `Arrays.hashCode(byte[])`: [1](#0-0) 

This 32-bit integer is used as the sole cache key on `findByEvmAddressOrAliasAndDeletedIsFalse`: [2](#0-1) 

The `CACHE_MANAGER_ENTITY` bean registers `CACHE_NAME_ALIAS` as a shared, process-wide Caffeine cache: [3](#0-2) 

The caller `CommonEntityAccessor.get(Bytes alias, ...)` passes arbitrary user-controlled bytes directly: [4](#0-3) 

**Root cause:** The cache key is a 32-bit integer (`int`). Spring's `@Cacheable` uses this integer as the map key with no further validation. After a cache hit, the framework returns the stored `Optional<Entity>` without verifying that the stored entry's originating byte array equals the current query's byte array. Two distinct byte arrays that produce the same `Arrays.hashCode` value are indistinguishable to the cache.

**Exploit flow:**
1. Victim's entity is populated into the cache under key `H = Arrays.hashCode(victimAddress)` (by any prior lookup — the victim's own transaction, a block explorer query, etc.).
2. Attacker computes a byte array `A ≠ victimAddress` such that `Arrays.hashCode(A) == H`. This is analytically solvable: for a fixed prefix, the final byte can be chosen to satisfy the polynomial congruence, or a birthday search over ~65,536 candidates suffices.
3. Attacker submits an `eth_call` or account query with alias bytes `A`.
4. `findByEvmAddressOrAliasAndDeletedIsFalse(A)` is called → cache key `H` hits → returns victim's `Entity` without touching the database.
5. The system resolves the attacker's address to the victim's entity for all downstream processing.

**Why existing checks fail:**
- `unless = "#result == null"`: The return type is `Optional<Entity>`, which is never `null`. Both `Optional.empty()` and `Optional.of(entity)` are cached unconditionally, meaning even empty results for a given hash permanently block the correct entity from being stored under that key.
- No post-hit equality check: Spring `@Cacheable` does not compare the stored key's originating input against the current input; it only compares the key object (the `int`). [5](#0-4) 

### Impact Explanation
An attacker who successfully collides with a victim's cache entry receives the victim's `Entity` object — including account ID, balance, alias, EVM address, and key material — for their own address lookup. In the web3 module's EVM simulation context (`eth_call`, `eth_getBalance`, smart contract execution), this causes:
- Incorrect balance reads: the attacker's address reports the victim's balance.
- Incorrect entity resolution in simulated EVM execution: token transfer simulations, allowance checks, and contract interactions that resolve `msg.sender` or target addresses via this path operate on the wrong entity.
- Cache poisoning (DoS variant): the attacker can pre-populate the cache with `Optional.empty()` under hash `H` before the victim's entity is ever cached, causing all subsequent legitimate lookups for the victim's address to return empty, effectively making the victim's account invisible to the EVM layer.

The mirror node is read-only and does not execute on-chain fund transfers directly; however, incorrect entity resolution in `eth_call` simulations can mislead dApps and wallets into displaying wrong balances or approving transactions based on false state, with downstream financial consequences.

### Likelihood Explanation
- **No privilege required:** Any user who can submit an `eth_call` or account query can trigger this.
- **Collision is trivial:** `Arrays.hashCode` over a 20-byte EVM address has a 32-bit output. A birthday attack requires ~65,536 random candidates. Analytical inversion (fixing a prefix and solving for the last byte) requires exactly 1 computation per target.
- **Cache persistence:** Caffeine caches are long-lived (configured via `cacheProperties.getEntity()`). A poisoned entry persists until eviction, affecting all users who query the victim's address during that window.
- **Repeatability:** The attacker can re-poison after eviction with no rate limiting on the cache key computation path.

### Recommendation
1. **Replace the cache key with a collision-resistant representation.** Use the full byte array encoded as a hex string or `Base64` string as the cache key, eliminating hash collisions entirely:
   ```java
   key = "T(java.util.Base64).getEncoder().encodeToString(#alias)"
   ```
2. **Alternatively, use `Arrays.toString(#alias)`** which produces a unique string per distinct byte array content and is natively supported in SpEL without a helper.
3. **Do not use `Arrays.hashCode` as a cache key for security-sensitive lookups.** A 32-bit hash is designed for hash-table bucket distribution, not for identity discrimination in a shared cache.
4. **Add a post-hit equality check** at the service layer if the cache key cannot be changed: after retrieving a cached entity, verify that the entity's `evm_address` or `alias` field actually equals the queried byte array before returning it.

### Proof of Concept

**Precondition:** Victim account has EVM address `V` (20 bytes). Their entity has been cached (e.g., by a prior `eth_getBalance(V)` call).

**Step 1 — Compute target hash:**
```java
byte[] victimAddress = hexToBytes("VICTIM_EVM_ADDRESS_20_BYTES");
int targetHash = Arrays.hashCode(victimAddress); // e.g., 0x1A2B3C4D
```

**Step 2 — Find colliding byte array (analytical, O(1)):**
```java
// Fix a 19-byte prefix P, solve for last byte b such that
// Arrays.hashCode(P || [b]) == targetHash
// hashCode = 31^1 * hashCode(P) + b  =>  b = targetHash - 31*hashCode(P)  (mod 256, treating as signed byte)
byte[] prefix = new byte[19]; // any 19 bytes
int prefixHash = 1;
for (byte byt : prefix) prefixHash = 31 * prefixHash + byt;
int needed = targetHash - 31 * prefixHash;
byte lastByte = (byte)(needed & 0xFF);
byte[] attackerBytes = Arrays.copyOf(prefix, 20);
attackerBytes[19] = lastByte;
assert Arrays.hashCode(attackerBytes) == targetHash;
assert !Arrays.equals(attackerBytes, victimAddress);
```

**Step 3 — Trigger cache hit:**
```
eth_call with `from` or target alias = attackerBytes (hex-encoded)
→ findByEvmAddressOrAliasAndDeletedIsFalse(attackerBytes)
→ cache key = targetHash → HIT → returns victim's Entity
```

**Step 4 — Observe:** The response contains the victim's account ID, balance, and entity fields, not the attacker's.

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L39-49)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_ALIAS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    @Query(value = """
            select *
            from entity
            where (evm_address = ?1 or alias = ?1) and deleted is not true
            """, nativeQuery = true)
    Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L99-105)
```java
    @Bean(CACHE_MANAGER_ENTITY)
    CacheManager cacheManagerEntity() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME, CACHE_NAME_EVM_ADDRESS, CACHE_NAME_ALIAS));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getEntity());
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
