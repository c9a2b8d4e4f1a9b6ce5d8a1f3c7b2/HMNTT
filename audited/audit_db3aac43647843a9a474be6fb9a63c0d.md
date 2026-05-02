### Title
32-bit `Arrays.hashCode` Cache Key Collision Enables Alias Cache Poisoning in `findByEvmAddressOrAliasAndDeletedIsFalse`

### Summary
`findByEvmAddressOrAliasAndDeletedIsFalse` uses `@spelHelper.hashCode(#alias)` — which resolves to Java's `Arrays.hashCode(byte[])`, a 32-bit polynomial hash — as the sole cache key for the `CACHE_NAME_ALIAS` Caffeine cache. Because the key space is only 2³² values, two distinct byte arrays that produce the same integer hash will share a cache slot. An unprivileged caller who queries a real entity whose address collides with a victim's target address will cause the cache to serve the wrong entity to the victim, silently redirecting alias resolution without any database query.

### Finding Description
**Exact location:**
- `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 39–49
- `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22

**Root cause:**
`SpelHelper.hashCode(byte[])` delegates to `Arrays.hashCode(value)`:
```java
// SpelHelper.java:20-22
public int hashCode(byte[] value) {
    return Arrays.hashCode(value);
}
```
`Arrays.hashCode` computes a 32-bit polynomial: `result = 31*result + b[i]` for each byte. The `@Cacheable` annotation stores the result under this integer key:
```java
// EntityRepository.java:39-49
@Cacheable(
    cacheNames = CACHE_NAME_ALIAS,
    cacheManager = CACHE_MANAGER_ENTITY,
    key = "@spelHelper.hashCode(#alias)",
    unless = "#result == null")
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```
Spring's cache layer uses the returned `int` as the map key. Two different `byte[]` inputs that produce the same `int` will collide on the same cache slot. The `unless = "#result == null"` guard only prevents caching empty results; it does **not** verify that a cache hit corresponds to the queried input.

**Collision construction (analytical):**
For any byte array `A` of length ≥ 2, a colliding array `B` can be constructed by modifying two adjacent bytes at positions `i` and `i+1`:
```
B[i]   = A[i]   + 1
B[i+1] = A[i+1] - 31
```
This satisfies `31*(B[i]-A[i]) + (B[i+1]-A[i+1]) = 31*1 + (-31) = 0`, so `Arrays.hashCode(A) == Arrays.hashCode(B)` exactly (not just mod 2³²), as long as both bytes remain in the valid range `[0, 255]`.

**Exploit flow:**
1. Attacker identifies entity `X` with EVM address `A` (public on-chain data).
2. Attacker computes `B` analytically such that `Arrays.hashCode(A) == Arrays.hashCode(B)` and `B` is the address of a different entity `Y` (or a target address a victim will query).
3. Attacker sends an `eth_call` / contract call that causes `findByEvmAddressOrAliasAndDeletedIsFalse(A)` to execute → entity `X` is stored in the cache under key `K = hashCode(A)`.
4. Victim sends a call resolving address `B` → `findByEvmAddressOrAliasAndDeletedIsFalse(B)` is invoked → cache key `K = hashCode(B) = K` → **cache hit returns entity `X`** instead of entity `Y`, no DB query is made.

**Why existing checks fail:**
- `unless = "#result == null"` only skips caching null; it does not validate that the cached entity's `evm_address` or `alias` field matches the queried `#alias` parameter.
- The Caffeine cache manager (`CACHE_MANAGER_ENTITY`) stores entries by the integer key with no secondary equality check on the original byte array.
- No eviction or invalidation logic is triggered by a collision.

### Impact Explanation
Any caller of `CommonEntityAccessor.get(Bytes alias, ...)` (line 49 of `CommonEntityAccessor.java`) that omits a timestamp will hit this cached path. A poisoned cache entry causes the EVM execution layer to resolve the wrong contract or account for a given alias. Concretely: a `CALL` or `STATICCALL` targeting address `B` will execute against the code and storage of entity `X` instead. This enables silent misdirection of contract calls, incorrect balance/nonce reads, and wrong authorization checks — all without any privileged access. The cache TTL is governed by `cacheProperties.getEntity()` (default `expireAfterAccess`), so the poisoned entry persists until eviction.

### Likelihood Explanation
The attack requires no special privileges — only the ability to send JSON-RPC requests (e.g., `eth_call`). Hedera entity addresses are public; an attacker can enumerate them via the mirror node REST API. Given the 32-bit hash space and the birthday bound (~65 536 entities for a 50% collision probability), a production network with millions of accounts will contain many naturally colliding pairs. Beyond natural collisions, the attacker can analytically construct a colliding address in O(1) by adjusting two bytes of any known address, making targeted poisoning straightforward. The attack is repeatable: after cache eviction the attacker simply re-queries `A` to re-poison.

### Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with the full byte array (or a collision-resistant representation). Spring's `SimpleKeyGenerator` handles `byte[]` by value if the key expression returns the array directly, but a safer approach is to use a hex-encoded string or `java.util.Arrays.toString`:

```java
// Option 1: use the byte array directly (Spring wraps it in SimpleKey)
key = "#alias"

// Option 2: hex-encode for a human-readable, collision-free key
key = "T(org.apache.commons.codec.binary.Hex).encodeHexString(#alias)"
```

Remove `SpelHelper.hashCode` from cache key expressions entirely, or replace it with a cryptographic digest (SHA-256 truncated to 128 bits) if a fixed-width key is required. Apply the same fix to `findByEvmAddressAndDeletedIsFalse` (line 35), which has the identical flaw.

### Proof of Concept
```
Precondition: Entity X exists with evm_address = [0x00, ..., 0x32, 0x64] (bytes 18,19 = 50,100).
              Entity Y exists with evm_address = [0x00, ..., 0x33, 0x45] (bytes 18,19 = 51,69).
              Arrays.hashCode([...,50,100]) == Arrays.hashCode([...,51,69])  ← verified analytically.

Step 1: Attacker sends eth_call with `to` = address(X).
        → findByEvmAddressOrAliasAndDeletedIsFalse([...,50,100]) executes DB query, returns X.
        → Cache stores: CACHE_NAME_ALIAS[K] = X   (K = Arrays.hashCode([...,50,100]))

Step 2: Victim sends eth_call with `to` = address(Y).
        → findByEvmAddressOrAliasAndDeletedIsFalse([...,51,69]) checks cache with key K.
        → Cache hit: returns X  ← WRONG ENTITY, no DB query performed.

Result: Victim's call executes against entity X's contract code/storage instead of Y's.
        Entity resolution is silently corrupted for the duration of the cache entry's lifetime.
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

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

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
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
