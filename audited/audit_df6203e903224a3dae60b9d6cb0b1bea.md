Looking at the actual code:

- `SpelHelper.hashCode(byte[])` calls `Arrays.hashCode(value)` — a 32-bit polynomial hash
- Used as the sole cache key in `EntityRepository` for `findByEvmAddressAndDeletedIsFalse` and `findByEvmAddressOrAliasAndDeletedIsFalse` [1](#0-0) [2](#0-1) 

---

### Title
Cache Key Collision via 32-bit `Arrays.hashCode` in `spelHelper` Allows Wrong Entity State to Be Served

### Summary
`SpelHelper.hashCode(byte[])` delegates to `Arrays.hashCode(byte[])`, a 32-bit polynomial hash, used as the sole cache key for EVM address and alias lookups in `EntityRepository`. Because the output space is only 2³² values, an unprivileged attacker can trivially compute two distinct EVM addresses that produce the same cache key, causing the cached entity/contract state of one address to be returned for a different address.

### Finding Description
`SpelHelper.hashCode(byte[])` at `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java:20-22` returns `Arrays.hashCode(value)`, a standard Java 32-bit polynomial hash (`result = 31 * result + b` for each byte). This value is used verbatim as the Spring `@Cacheable` key in two methods:

```java
// EntityRepository.java:35-36
key = "@spelHelper.hashCode(#alias)"
Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);

// EntityRepository.java:42-43
key = "@spelHelper.hashCode(#alias)"
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

The `unless = "#result == null"` guard only prevents caching null results; it does not prevent two distinct byte arrays from mapping to the same integer key. When entity A (address `addrA`) is cached under key `K`, and an attacker supplies `addrB` where `Arrays.hashCode(addrB) == K`, the cache returns entity A's data for the lookup of `addrB`.

For the null case: `Arrays.hashCode(null)` returns `0` (no NPE), so a null alias produces cache key `0`, which can collide with any legitimate entity whose alias also hashes to `0`.

### Impact Explanation
An attacker who controls the EVM address or alias parameter in a web3 API call can receive wrong entity state (wrong contract, wrong account) from the cache. In a smart contract context, this means `eth_call` or similar RPC methods could return state belonging to a different contract — incorrect balances, storage values, or bytecode pointers — without any funds being directly at risk but with potential for incorrect smart contract behavior and data integrity violations.

### Likelihood Explanation
`Arrays.hashCode` over a 20-byte EVM address is a linear congruential computation with 2³² possible outputs. By the birthday paradox, ~65,536 random addresses yield a ~50% collision probability. The hash is also analytically invertible: given a target hash value `K` and a prefix of bytes, the remaining bytes can be solved algebraically. An unprivileged user making standard JSON-RPC calls (no authentication required) can trigger this with precomputed colliding addresses.

### Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with a collision-resistant representation. Options:
1. Use `Arrays.toString(alias)` or `HexFormat.of().formatHex(alias)` as the cache key (unique string per byte array).
2. Use a cryptographic hash (e.g., SHA-256 truncated to 64 bits) in `SpelHelper.hashCode`.
3. Use Spring's `SimpleKey` wrapping the full byte array, which uses `Arrays.equals`/`Arrays.hashCode` internally but combined with the array length and content for equality checks — though this still uses 32-bit hash for bucketing, equality is checked by content, so Spring's cache would not serve wrong results as long as the cache implementation checks equality. Verify the Caffeine cache uses `.equals()` for key comparison, not just hash equality.

The safest fix is option 1: return a hex string from `spelHelper` so the key is globally unique.

### Proof of Concept
1. Find two 20-byte EVM addresses `addrA` and `addrB` such that `Arrays.hashCode(addrA) == Arrays.hashCode(addrB)`. This is trivially achievable offline by brute force in milliseconds given the 32-bit output space.
2. Send a web3 API request (e.g., `eth_getCode` or `eth_call`) targeting `addrA`. The result is cached under key `K = Arrays.hashCode(addrA)`.
3. Send a web3 API request targeting `addrB`. The cache lookup finds key `K` and returns entity A's data instead of querying the database for entity B.
4. The response for `addrB` contains entity A's contract state, demonstrating cache poisoning via hash collision. [1](#0-0) [2](#0-1)

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L32-49)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_EVM_ADDRESS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
    Optional<Entity> findByEvmAddressAndDeletedIsFalse(byte[] alias);

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
