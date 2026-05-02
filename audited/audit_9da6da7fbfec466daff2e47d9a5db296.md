### Title
Cache Poisoning via 32-bit Hash Collision in SpelHelper-Keyed Entity Cache

### Summary
`SpelHelper.hashCode(byte[])` delegates to `Arrays.hashCode()`, producing a 32-bit integer used as the sole cache key for EVM address and alias entity lookups in `EntityRepository`. Because the 32-bit output space (2^32) is trivially collided against 20-byte EVM address inputs (2^160), an unprivileged attacker who can create Hedera accounts can poison the shared Caffeine cache, causing subsequent lookups for a victim's EVM address to return a different entity's data.

### Finding Description

**Exact code path:**

`SpelHelper.hashCode` at [1](#0-0)  returns `Arrays.hashCode(value)` — a 32-bit polynomial hash.

This value is used as the **sole** cache key in two repository methods: [2](#0-1) [3](#0-2) 

Both caches (`evmAddress`, `alias`) are backed by a shared, long-lived Caffeine instance registered in `CACHE_MANAGER_ENTITY`: [4](#0-3) 

**Root cause:** `Arrays.hashCode` for a `byte[]` computes `result = 31 * result + b` for each byte — a non-cryptographic 32-bit polynomial. For 20-byte EVM addresses, the input space is 2^160 but the key space is only 2^32. Collisions are guaranteed and computationally trivial to find (~2^16 attempts via birthday attack).

**Failed assumption:** The design assumes `Arrays.hashCode` produces unique keys for distinct EVM addresses. It does not. The `unless = "#result == null"` guard only prevents caching of DB misses; it does nothing to prevent two distinct existing addresses from sharing the same cache slot.

**Exploit flow:**
1. Attacker generates ECDSA key pairs offline, computing their Ethereum-style EVM addresses.
2. Using the birthday bound (~65,536 pairs), attacker finds two addresses A and B where `Arrays.hashCode(A) == Arrays.hashCode(B)`.
3. Attacker creates a Hedera account for address A (requires only HBAR, no privilege).
4. Attacker sends a request to the mirror node web3 API (`POST /api/v1/contracts/call` with `to` = address A), triggering `findByEvmAddressAndDeletedIsFalse(A)` or `findByEvmAddressOrAliasAndDeletedIsFalse(A)`. The result (entity for A) is cached under key `hashCode(A)`.
5. Any subsequent request resolving address B hits the cache with key `hashCode(B) == hashCode(A)` and receives entity A's data instead of entity B's data.

### Impact Explanation

The entity cache is shared across all requests. A poisoned entry persists for the cache TTL (configured via `cacheProperties.getEntity()`). Any caller resolving address B — including EVM contract execution, balance checks, and alias resolution — receives the wrong `Entity` object. This can cause:
- Wrong contract bytecode or account data returned for EVM calls
- Incorrect balance or key information served to users
- Misdirected HBAR transfers if the wrong entity ID is resolved during contract execution

Severity: **Medium-High** — directly corrupts entity resolution for the web3 API, affecting financial correctness of contract call results.

### Likelihood Explanation

The attack requires no special privilege — only the ability to create Hedera accounts (standard network access with HBAR). Finding a collision pair takes ~65,536 key-pair generations, which is trivial on commodity hardware in seconds. The attacker does not need to know the victim's address in advance; they can pre-generate a large collision table and register accounts for one side of each pair, creating a probabilistic trap. The attack is repeatable and the cache is not invalidated between requests.

### Recommendation

Replace the 32-bit `Arrays.hashCode` cache key with the full byte array content as the key. Spring's default key generation for `byte[]` arguments already uses `Arrays.equals`-compatible wrappers. Specifically:

1. Remove the `key = "@spelHelper.hashCode(#alias)"` attribute from both `@Cacheable` annotations in `EntityRepository`, allowing Spring's `SimpleKeyGenerator` to use the full byte array value.
2. Alternatively, wrap the byte array in a `ByteBuffer` or use `HexFormat.of().formatHex(alias)` as the key — both provide collision-free, content-based equality.
3. If `SpelHelper.hashCode` is retained for other purposes, document that it must never be used as a sole cache key.

### Proof of Concept

```java
// Step 1: Find two 20-byte EVM addresses with the same Arrays.hashCode
// (birthday attack — ~65536 random addresses suffice)
import java.util.Arrays;
import java.util.HashMap;
import java.util.Random;

Random rng = new Random();
HashMap<Integer, byte[]> seen = new HashMap<>();
byte[] collision = null, original = null;

while (collision == null) {
    byte[] addr = new byte[20];
    rng.nextBytes(addr);
    int h = Arrays.hashCode(addr);
    if (seen.containsKey(h)) {
        original = seen.get(h);
        collision = addr;
    } else {
        seen.put(h, addr);
    }
}
// original and collision are two distinct 20-byte addresses with identical Arrays.hashCode

// Step 2: Create a Hedera account whose EVM address == toHex(original)
// Step 3: POST /api/v1/contracts/call with "to" = toHex(original)
//         → entity for `original` is now cached under hashCode(original)
// Step 4: POST /api/v1/contracts/call with "to" = toHex(collision)
//         → cache hit returns entity for `original` instead of entity for `collision`
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
