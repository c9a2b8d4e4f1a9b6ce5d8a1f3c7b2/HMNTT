### Title
32-bit `Arrays.hashCode` Cache Key Collision in `CACHE_NAME_EVM_ADDRESS` Allows Wrong Entity to Be Served for Distinct EVM Addresses

### Summary
`findByEvmAddressAndDeletedIsFalse` uses `@spelHelper.hashCode(#alias)` — which resolves to Java's `Arrays.hashCode(byte[])`, a 32-bit polynomial hash — as the sole cache key for `CACHE_NAME_EVM_ADDRESS`. Because the output space is only 2^32 values while EVM addresses occupy 2^160, an attacker can analytically compute a second 20-byte address that collides with any target address. Once entity A is cached under the colliding key, all subsequent lookups for address B (same hash) return A's entity data without hitting the database, causing incorrect EVM execution state.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode` at [1](#0-0)  delegates directly to `Arrays.hashCode(byte[])`, returning a signed 32-bit `int`.

This 32-bit integer is used as the **sole cache key** in: [2](#0-1) 

Spring's `@Cacheable` performs no secondary validation — it returns the cached `Optional<Entity>` directly when the key matches, regardless of whether the stored entity's actual EVM address matches the queried `alias`.

**Root cause:** `Arrays.hashCode(byte[])` computes:
```
result = 1
for each byte b: result = 31 * result + b   (mod 2^32)
```
This is a 32-bit polynomial hash over 20-byte (160-bit) inputs. Collisions are analytically trivial: given address A with bytes `[..., a18, a19]`, address B `[..., a18+1, a19-31]` produces an identical hash (since `31*(a18-(a18+1)) + (a19-(a19-31)) = -31+31 = 0`). No brute force is needed.

**Why `unless = "#result == null"` is insufficient:** This guard only prevents caching of empty results. Once a non-null entity for address A is stored under key `hashCode(A)`, any address B with `hashCode(B) == hashCode(A)` retrieves A's entity — the guard never re-validates the stored value against the new input.

**Call chain to EVM execution:** [3](#0-2) 

`getEntityByEvmAddressTimestamp` → `findByEvmAddressAndDeletedIsFalse` is the live (non-historical) path used during EVM contract calls.

### Impact Explanation
A cache collision causes the mirror node to return entity A's data (contract bytecode, balance, key, type) when address B is queried. Downstream EVM execution operates on the wrong entity: wrong bytecode may be executed, wrong balances returned, wrong account type used for permission checks. Every mirror node instance that has cached the poisoned entry serves incorrect state for all subsequent callers of address B until the cache expires. Since the Caffeine cache is per-instance in-memory, all instances receiving traffic for address A will be poisoned independently.

### Likelihood Explanation
No privileged access is required. An attacker needs only:
1. The ability to deploy a contract (via CREATE2) or create an account — both are standard unprivileged operations on Hedera.
2. Knowledge of a target address B to collide with (publicly observable on-chain).
3. ~65,536 CREATE2 salt iterations (birthday bound for 2 bytes) to land address A at the analytically derived collision point — or zero iterations using the direct algebraic solution above.

The hash function is public, deterministic, and has no secret component. The attack is repeatable and scriptable.

### Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with the full byte array content as the key, so distinct addresses never share a key:

```java
// Instead of:
key = "@spelHelper.hashCode(#alias)"

// Use the raw bytes as key (Spring will use Arrays.equals for comparison):
key = "T(java.util.Arrays).toString(#alias)"
// or wrap in a ByteBuffer/ByteArrayWrapper with proper equals/hashCode
```

Alternatively, use `java.util.Arrays.hashCode` only as a secondary bucket discriminator and store the full byte array for equality checking, or switch to a `ByteBuffer`-wrapped key (which uses `Arrays.equals` internally). The fix must ensure two distinct byte arrays never map to the same cache entry.

### Proof of Concept

```java
// Step 1: Find colliding addresses analytically
byte[] addressA = new byte[20];
// ... set addressA to any desired 20 bytes, e.g. a deployed contract
// Ensure addressA[18] >= -127 (so addressA[18]+1 fits in byte)
// and addressA[19] <= 96 (so addressA[19]-31 fits in byte)

byte[] addressB = addressA.clone();
addressB[18] = (byte)(addressA[18] + 1);
addressB[19] = (byte)(addressA[19] - 31);

// Verify collision:
assert java.util.Arrays.hashCode(addressA) == java.util.Arrays.hashCode(addressB);

// Step 2: Register entity with addressA on Hedera (CREATE2 or account creation)
// Step 3: Trigger a query for addressA via the web3 JSON-RPC endpoint:
//   eth_call targeting addressA → entity A is now cached under hashCode(A)
// Step 4: Query addressB:
//   eth_call targeting addressB → cache hit returns entity A's data
//   → EVM executes with entity A's bytecode/balance/type for address B
``` [2](#0-1) [1](#0-0)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
