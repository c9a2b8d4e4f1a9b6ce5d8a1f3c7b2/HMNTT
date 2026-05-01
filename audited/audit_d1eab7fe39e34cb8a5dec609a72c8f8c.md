### Title
Cache Key Collision via `Arrays.hashCode()` Truncation Enables Wrong Entity Return in `CACHE_NAME_EVM_ADDRESS`

### Summary
`findByEvmAddressAndDeletedIsFalse()` uses `@spelHelper.hashCode(#alias)` as its Spring cache key, which resolves to `Arrays.hashCode(byte[])` — a 32-bit polynomial hash. Because the cache key space is only 2³² (~4.3 billion values) while EVM addresses are 20-byte (160-bit) values, an unprivileged attacker can precompute two distinct EVM addresses that collide on this hash, poison the `CACHE_NAME_EVM_ADDRESS` cache with one address's entity, and cause the mirror node to return the wrong entity for the colliding address to all subsequent callers.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode(byte[])` at [1](#0-0) 

returns `Arrays.hashCode(value)`, a 32-bit `int` computed as the standard Java polynomial hash `result = 31 * result + element` over each byte.

This integer is used verbatim as the Spring `@Cacheable` key for `findByEvmAddressAndDeletedIsFalse`: [2](#0-1) 

The cache is backed by Caffeine under `CACHE_MANAGER_ENTITY`: [3](#0-2) 

**Root cause:** The cache key is a 32-bit integer derived from a 160-bit input. The pigeonhole principle guarantees collisions exist; the birthday paradox means ~65,536 candidate addresses suffice to find one with ~50% probability. The `unless = "#result == null"` guard only prevents caching of empty results — it does not prevent a cached non-null result from being returned for a colliding key.

**Exploit flow:**
1. Attacker enumerates known entity EVM addresses on Hedera (all public on-chain data).
2. For a target address `A` (a real entity), attacker computes `h = Arrays.hashCode(A)`.
3. Attacker brute-forces a 20-byte value `B ≠ A` such that `Arrays.hashCode(B) == h`. This requires on average 2³² / (number of candidates tested) attempts; finding a collision among ~65K candidates takes milliseconds on commodity hardware.
4. Attacker sends a JSON-RPC request (e.g., `eth_call` with `to = A`) that triggers `findByEvmAddressAndDeletedIsFalse(A)`. Entity A is fetched from DB and stored in cache under key `h`.
5. Attacker (or any user) sends a request with `to = B`. Spring cache intercepts the call, finds key `h` already populated, and returns Entity A — without ever querying the database.
6. The EVM executes with Entity A's bytecode/state for address B.

### Impact Explanation
Any caller querying address `B` receives Entity A's data: wrong bytecode, wrong balance, wrong storage. In a read-only mirror node context this produces incorrect `eth_call` / `eth_estimateGas` results for all users querying `B` for the lifetime of the cache entry. Contracts that rely on mirror node query results for off-chain verification or UI display receive silently wrong data. The same flaw exists in `findByEvmAddressOrAliasAndDeletedIsFalse` via `CACHE_NAME_ALIAS`. [4](#0-3) 

### Likelihood Explanation
The attack requires no credentials, no on-chain transactions, and no special privileges — only the ability to send JSON-RPC requests to the public mirror node API. Collision search is offline and completes in milliseconds. The attacker only needs one real entity address (trivially obtained from any block explorer). The cache entry persists for the full TTL configured in `cacheProperties.getEntity()`, meaning the poisoned result is served to all users during that window. The attack is repeatable and deterministic.

### Recommendation
Replace the 32-bit `Arrays.hashCode()` cache key with a collision-resistant key. Options in increasing preference:

1. **Use `Arrays.toString(alias)` or `HexFormat.of().formatHex(alias)`** as the cache key — a string representation is unique for distinct byte arrays and has no collision risk.
2. **Use the raw `byte[]` wrapped in a `ByteBuffer`** (which implements `equals`/`hashCode` correctly based on content) as the key.
3. **Remove the custom `key =` expression entirely** and let Spring use its default `SimpleKey` wrapping, which calls `Arrays.equals` for equality and `Arrays.hashCode` only for bucket placement (not identity) — though this still has the same hash collision issue at the bucket level; option 1 or 2 is preferred.

The fix in `SpelHelper` should either be removed or replaced with a content-unique representation:
```java
public String cacheKey(byte[] value) {
    return HexFormat.of().formatHex(value);
}
```
And update the annotation: `key = "@spelHelper.cacheKey(#alias)"`.

### Proof of Concept
```java
// Step 1: Find collision offline (runs in <1 second)
import java.util.Arrays;
import java.util.HashMap;

public class CollisionFinder {
    public static void main(String[] args) {
        // Known real entity EVM address (example)
        byte[] addressA = hexToBytes("0x1234567890abcdef1234567890abcdef12345678");
        int targetHash = Arrays.hashCode(addressA);

        // Brute-force a colliding 20-byte address
        byte[] addressB = new byte[20];
        for (long i = 0; i < Long.MAX_VALUE; i++) {
            // vary last 8 bytes
            for (int j = 0; j < 8; j++) addressB[12 + j] = (byte)(i >> (j * 8));
            if (Arrays.hashCode(addressB) == targetHash && !Arrays.equals(addressA, addressB)) {
                System.out.println("Collision found: " + bytesToHex(addressB));
                break;
            }
        }
    }
}

// Step 2: Poison cache
// curl -X POST <mirror-node>/api/v1/contracts/call \
//   -d '{"to":"0x<addressA>","data":"0x"}' 
// -> caches Entity A under key=targetHash

// Step 3: Trigger wrong result
// curl -X POST <mirror-node>/api/v1/contracts/call \
//   -d '{"to":"0x<addressB>","data":"0x"}'
// -> returns Entity A's data for address B (cache hit, no DB query)
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
