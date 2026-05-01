### Title
Cache Key Hash Collision in `findByEvmAddressOrAliasAndDeletedIsFalse` Enables Cache Poisoning and Wrong Entity Return

### Summary
The `CACHE_NAME_ALIAS` cache for `findByEvmAddressOrAliasAndDeletedIsFalse` uses a 32-bit `Arrays.hashCode()` integer as the sole cache key. Because `Arrays.hashCode(byte[])` has only 2^32 possible values and collisions are analytically trivial to compute, an unprivileged attacker can craft an alias byte array that collides with a cached entry, either receiving a wrong entity object or pre-poisoning the cache so that a legitimate alias lookup returns `Optional.empty()` instead of the real entity.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode` at `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java` lines 20–22:
```java
public int hashCode(byte[] value) {
    return Arrays.hashCode(value);  // 32-bit int
}
``` [1](#0-0) 

`findByEvmAddressOrAliasAndDeletedIsFalse` at `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java` lines 39–49:
```java
@Cacheable(
        cacheNames = CACHE_NAME_ALIAS,
        cacheManager = CACHE_MANAGER_ENTITY,
        key = "@spelHelper.hashCode(#alias)",   // ← sole key = 32-bit int
        unless = "#result == null")
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
``` [2](#0-1) 

**Root cause:** `Arrays.hashCode(byte[])` is a polynomial hash `result = 31*result + b` over a 32-bit integer space. The entire cache key is this single integer. Two distinct byte arrays that produce the same integer are treated as the same cache entry. Spring Cache with Caffeine stores and retrieves by this key with no secondary equality check on the actual byte array.

**Failed assumption:** The code assumes `Arrays.hashCode()` is collision-free for the alias inputs it will receive. It is not — collisions are analytically computable in O(1).

**Collision example:**
- `Arrays.hashCode([0, 31])` = 31×(31×1 + 0) + 31 = **992**
- `Arrays.hashCode([1, 0])` = 31×(31×1 + 1) + 0 = **992**

Any two byte arrays `X` and `Y` where `31*(X[i]-Y[i]) = Y[i+1]-X[i+1]` (mod 2^32) collide.

**Exploit flow — cache poisoning DoS:**
1. Attacker identifies target alias `X` of a real entity (aliases are public on-chain).
2. Attacker computes alias `Y` (arbitrary bytes, no real entity) such that `Arrays.hashCode(Y) == Arrays.hashCode(X)`.
3. Attacker sends a request using alias `Y` before any legitimate request for `X` has populated the cache.
4. DB lookup for `Y` returns no entity → `Optional.empty()` is returned and **cached** under key `hashCode(Y) == hashCode(X)`.
5. All subsequent legitimate requests for alias `X` hit the cache and receive `Optional.empty()` — the real entity is never fetched from DB until the cache entry expires.

**Exploit flow — wrong entity return:**
1. Entity A (alias `X`) is already cached under key `H = Arrays.hashCode(X)`.
2. Attacker sends a request with alias `Y` where `Arrays.hashCode(Y) == H`.
3. Cache hit → Entity A is returned for alias `Y`.

**Why existing checks fail:**
- `unless = "#result == null"` only suppresses caching of Java `null`. Spring Data JPA returns `Optional.empty()` (not `null`) when no entity is found, so "not found" results **are** cached and can poison the slot. [3](#0-2) 
- There is no secondary verification of the actual alias bytes after a cache hit; the cached `Optional<Entity>` is returned directly.
- The same flaw exists identically in `findByEvmAddressAndDeletedIsFalse` (lines 32–37, `CACHE_NAME_EVM_ADDRESS`). [4](#0-3) 

### Impact Explanation
- **Cache poisoning DoS**: An attacker can make any entity unreachable via alias lookup for the duration of the cache TTL by pre-populating the cache slot with a colliding non-existent alias. This affects `eth_call`, balance queries, and any EVM execution path that resolves accounts by alias through `CommonEntityAccessor.get(Bytes, Optional<Long>)`. [5](#0-4) 
- **Wrong entity returned**: A query with a crafted alias returns a different entity's full object, causing incorrect EVM execution results (wrong balance, wrong contract state) for callers relying on alias-based resolution.
- Severity: **Medium–High**. No authentication is required; the attack is repeatable; it affects correctness and availability of the web3 API for targeted accounts.

### Likelihood Explanation
- Hedera account aliases are public (visible in transaction records and the mirror node REST API), so an attacker can enumerate targets.
- Computing a colliding alias is O(1) arithmetic — no brute force needed.
- The attacker only needs to send a single HTTP request with the crafted alias to poison the cache slot.
- The attack must be repeated each cache TTL cycle to maintain the DoS, but this is trivially automatable.
- No special privileges, credentials, or network position are required.

### Recommendation
Replace the 32-bit hash with the full byte array as the cache key, using a collision-resistant representation:

```java
// Option 1: use hex string of the alias as the key (unambiguous, no collisions)
key = "T(org.apache.commons.codec.binary.Hex).encodeHexString(#alias)"

// Option 2: use java.util.Arrays.toString(#alias) — verbose but collision-free for distinct arrays
key = "T(java.util.Arrays).toString(#alias)"
```

Alternatively, wrap the `byte[]` in a `ByteBuffer` or a value object that implements `equals`/`hashCode` correctly using the full content, and use that as the key. The fix must be applied to both `findByEvmAddressOrAliasAndDeletedIsFalse` (line 42) and `findByEvmAddressAndDeletedIsFalse` (line 35).

### Proof of Concept

**Precondition**: Entity with alias `[1, 0]` (2-byte alias, for illustration) exists in the database and has not yet been cached.

**Steps**:
```
# Step 1: Compute colliding alias
# Arrays.hashCode([0, 31]) == Arrays.hashCode([1, 0]) == 992

# Step 2: Send eth_call or balance request resolving alias [0, 31]
# (no entity exists for [0, 31])
# → DB returns Optional.empty()
# → Optional.empty() stored in CACHE_NAME_ALIAS under key 992

# Step 3: Send eth_call or balance request resolving alias [1, 0]
# (real entity exists)
# → Cache HIT on key 992 → returns Optional.empty()
# → Entity is NOT found; request fails or returns zero balance
# → DB is never queried for the real entity
```

**Verification**: Repeat Step 3 multiple times within the cache TTL window; all return "not found." After cache expiry, Step 3 returns the correct entity, confirming the issue is cache-layer only and not a DB bug.

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L32-37)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_EVM_ADDRESS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
