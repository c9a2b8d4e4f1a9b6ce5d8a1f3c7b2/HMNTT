All three code references are confirmed in the repository. Here is the evaluation:

**Confirmed code facts:**

1. `SpelHelper.hashCode(byte[])` returns `Arrays.hashCode(value)` — a 32-bit integer. [1](#0-0) 

2. `findByEvmAddressAndDeletedIsFalse` uses `@spelHelper.hashCode(#alias)` as the sole cache key. [2](#0-1) 

3. `findByEvmAddressOrAliasAndDeletedIsFalse` uses the same sole cache key. [3](#0-2) 

4. The `unless = "#result == null"` guard does not prevent collision-based cache hits. [4](#0-3) 

The vulnerability is real and all claims check out against the actual code.

---

## Audit Report

## Title
Cache Poisoning via `Arrays.hashCode` Collision in SpEL Cache Key for EVM Address Lookups

## Summary
`SpelHelper.hashCode(byte[])` returns `Arrays.hashCode(value)`, a 32-bit integer. This integer is used as the **sole** Spring `@Cacheable` key for two entity repository methods that look up entities by EVM address. Two distinct byte arrays that collide on this 32-bit hash share the same cache entry, allowing an attacker to cause the cache to return the wrong entity for a queried EVM address.

## Finding Description

**Exact code path:**

`SpelHelper.hashCode` at `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java` (lines 20–22) delegates directly to `Arrays.hashCode(value)`, which computes a degree-N polynomial over a 32-bit ring (multiplier 31). The output space is only 2^32. [1](#0-0) 

This integer is used as the sole `key` in two `@Cacheable` annotations:

- `findByEvmAddressAndDeletedIsFalse(byte[] alias)` — cache name `CACHE_NAME_EVM_ADDRESS`
- `findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias)` — cache name `CACHE_NAME_ALIAS` [5](#0-4) 

**Root cause:** The cache key is a lossy 32-bit projection of a 20-byte (160-bit) input. `Arrays.hashCode` is not a collision-resistant function. For 20-byte inputs, the birthday bound for collisions is approximately 2^16 (~65,536) random samples. Collisions can also be computed analytically by solving the linear equation over Z/2^32Z.

**Failed assumption:** The cache key is assumed to uniquely identify the input byte array. It does not.

**Exploit flow:**
1. Attacker offline-computes two distinct 20-byte EVM addresses A and B where `Arrays.hashCode(A) == Arrays.hashCode(B)`, and A maps to a real entity E_A in the system.
2. Attacker sends a request triggering `findByEvmAddressAndDeletedIsFalse(A)`. The result E_A is stored in the Caffeine cache under the integer key `hashCode(A)`.
3. A victim sends a request for address B. Spring's `@Cacheable` computes `hashCode(B) == hashCode(A)`, finds a cache hit, and returns E_A **without querying the database**.
4. The victim receives entity data for E_A instead of the correct entity for B.

**Why existing checks are insufficient:**

The `unless = "#result == null"` guard only prevents caching null results. It performs no collision detection and no secondary key verification. Once a non-null result is cached under a hash value, any other input with the same hash retrieves it unconditionally. [4](#0-3) 

## Impact Explanation
Any caller of the web3 JSON-RPC API (no authentication required) can receive incorrect entity data — wrong account balances, wrong contract bytecode, wrong key material — for an EVM address they legitimately queried. In the context of `eth_call` / `eth_getBalance` / contract simulation (routed through `CommonEntityAccessor.get`), this produces silently wrong execution results. The poisoned cache entry persists until eviction, affecting all users who query the colliding address during that window. [6](#0-5) 

## Likelihood Explanation
`Arrays.hashCode` collision pairs for 20-byte arrays are trivially computable: the hash is a public, deterministic, linear function over Z/2^32Z. An attacker needs no privileges, no special network position, and no authentication. The only precondition is knowing one valid EVM address in the system, which is public on-chain data. The attack is repeatable and scriptable.

## Recommendation
Replace the lossy 32-bit integer cache key with a collision-resistant representation of the byte array. The simplest correct fix is to change `SpelHelper.hashCode(byte[])` to return a hex-encoded `String` (or a `ByteBuffer`, which implements `equals`/`hashCode` by content), and rename the method accordingly:

```java
// In SpelHelper.java
public String toHex(byte[] value) {
    return HexFormat.of().formatHex(value);
}
```

And update the `@Cacheable` key expressions in `EntityRepository`:

```java
key = "@spelHelper.toHex(#alias)"
```

This ensures the cache key is a full-fidelity, collision-resistant representation of the input byte array.

## Proof of Concept
The following demonstrates that two distinct 20-byte arrays can share the same `Arrays.hashCode`:

```java
import java.util.Arrays;

public class CollisionDemo {
    public static void main(String[] args) {
        // Analytically solve for B given A such that Arrays.hashCode(A) == Arrays.hashCode(B)
        // Arrays.hashCode for byte[] computes:
        //   result = 1
        //   for each b: result = 31 * result + (b & 0xFF)
        // Modify the last two bytes of A to produce a collision.

        byte[] A = new byte[20]; // known valid EVM address (all zeros for demo)
        Arrays.fill(A, (byte) 0x01);

        byte[] B = A.clone();
        // Adjust bytes at positions 18 and 19 to produce same hash
        // 31 * x + b18_new = 31 * x + b18_old  =>  solve over Z/2^32Z
        // Simple brute-force for demonstration:
        int targetHash = Arrays.hashCode(A);
        outer:
        for (int i = 0; i < 256; i++) {
            for (int j = 0; j < 256; j++) {
                B[18] = (byte) i;
                B[19] = (byte) j;
                if (!Arrays.equals(A, B) && Arrays.hashCode(B) == targetHash) {
                    System.out.println("Collision found!");
                    System.out.println("hashCode(A) = " + targetHash);
                    System.out.println("hashCode(B) = " + Arrays.hashCode(B));
                    break outer;
                }
            }
        }
    }
}
```

Running this will find a collision pair within the 256×256 search space over the last two bytes, confirming the attack is trivially executable offline.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L29-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Address address, final Optional<Long> timestamp) {
        final var addressBytes = address.toArrayUnsafe();
        if (ConversionUtils.isLongZeroAddress(addressBytes)) {
            return getEntityByMirrorAddressAndTimestamp(address, timestamp);
        } else {
            return getEntityByEvmAddressTimestamp(address.toArrayUnsafe(), timestamp);
        }
    }

    public @NonNull Optional<Entity> get(@NonNull final AccountID accountID, final Optional<Long> timestamp) {
        if (accountID.hasAccountNum()) {
            return get(toEntityId(accountID), timestamp);
        } else {
            return get(accountID.alias(), timestamp);
        }
    }

    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
