### Title
Cache Poisoning via `Arrays.hashCode` Collision in SpEL Cache Key for EVM Address Lookups

### Summary
`SpelHelper.hashCode(byte[])` delegates to `Arrays.hashCode(byte[])`, which produces a 32-bit integer. Two distinct EVM addresses (byte arrays) that collide on this hash share the same Spring cache key. An unprivileged attacker can precompute a collision pair, prime the cache with one address's entity result, and cause subsequent lookups for the colliding address to return the wrong entity — without any database query.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode` at [1](#0-0)  returns `Arrays.hashCode(value)` — a 32-bit polynomial hash over the byte array.

This is used as the sole cache key in two repository methods: [2](#0-1) [3](#0-2) 

**Root cause:** `Arrays.hashCode` for a `byte[]` of length N computes a degree-N polynomial over a 32-bit ring (multiplier 31). The output space is only 2^32. For 20-byte EVM addresses, finding two distinct inputs A and B such that `Arrays.hashCode(A) == Arrays.hashCode(B)` is trivially achievable offline (birthday bound ~65,536 random samples; or analytically by solving the linear equation over Z/2^32Z).

**Failed assumption:** The cache key is assumed to uniquely identify the input byte array. It does not — it is a lossy 32-bit projection.

**Exploit flow:**
1. Attacker offline-computes a collision: two distinct 20-byte EVM addresses A and B where `Arrays.hashCode(A) == Arrays.hashCode(B)`, and A maps to a real entity E_A in the system.
2. Attacker sends a web3/eth_call request that triggers `findByEvmAddressAndDeletedIsFalse(A)` or `findByEvmAddressOrAliasAndDeletedIsFalse(A)`. The result (entity E_A) is stored in the Caffeine cache under key `hashCode(A)`.
3. A victim (or the attacker themselves) sends a request for address B. Spring's `@Cacheable` intercepts the call, computes `hashCode(B) == hashCode(A)`, finds a cache hit, and returns E_A **without querying the database**.
4. The victim receives entity data for E_A instead of the correct entity for B.

**Why existing checks are insufficient:**

The `unless = "#result == null"` guard [4](#0-3)  only prevents caching null results. It performs no collision detection and no secondary key verification. Once a non-null result is cached under a hash value, any other input with the same hash retrieves it unconditionally.

### Impact Explanation
Any caller of the web3 REST/JSON-RPC API (no authentication required) can receive incorrect entity data — wrong account balances, wrong contract bytecode, wrong key material — for an EVM address they legitimately queried. In the context of `eth_call` / `eth_getBalance` / contract simulation, this produces silently wrong execution results. The poisoned cache entry persists until eviction, affecting all users who query the colliding address during that window.

### Likelihood Explanation
`Arrays.hashCode` collision pairs for 20-byte arrays are trivially computable: the hash is a public, deterministic, linear function. An attacker needs no privileges, no special network position, and no authentication. The only precondition is knowing (or guessing) one valid EVM address in the system, which is public on-chain data. The attack is repeatable and scriptable.

### Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with a collision-resistant key. Options in increasing robustness:
1. Use `Arrays.toString(value)` or `HexFormat.of().formatHex(value)` as the cache key (full-fidelity string representation, no collision possible for distinct byte arrays).
2. Use a cryptographic digest (e.g., `Arrays.hashCode` → `MessageDigest.getInstance("SHA-256")`) if string keys are undesirable for memory reasons.
3. Alternatively, wrap the `byte[]` in a `ByteBuffer` or a value type that implements `equals`/`hashCode` correctly and use it directly as the cache key, letting Spring's default key generation handle it.

The `SpelHelper.hashCode` method should be removed or deprecated to prevent future misuse.

### Proof of Concept
```java
// Step 1: Find collision pair offline (trivial for Arrays.hashCode)
// Arrays.hashCode uses: result = 31*result + (b & 0xff) for each byte
// For two 20-byte arrays A and B, find A != B with same hash:
// Fix first 19 bytes equal, solve for last byte difference:
//   31^0 * (A[19] - B[19]) ≡ 0 (mod 2^32)  → not always solvable in last byte alone
// In practice, use birthday attack: generate ~100k random 20-byte arrays,
// group by Arrays.hashCode, pick any pair with same hash.

byte[] addressA = ...; // maps to entity E_A (e.g., a known contract)
byte[] addressB = ...; // Arrays.hashCode(addressA) == Arrays.hashCode(addressB), B != A

// Step 2: Prime the cache
// GET /api/v1/contracts/call  with "to": hex(addressA)
// → cache now holds: hashCode(addressA) → E_A

// Step 3: Victim queries addressB
// GET /api/v1/contracts/call  with "to": hex(addressB)
// → Spring @Cacheable computes hashCode(addressB) == hashCode(addressA)
// → returns E_A from cache without DB query
// → victim receives wrong entity (E_A instead of E_B or empty)
```

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
