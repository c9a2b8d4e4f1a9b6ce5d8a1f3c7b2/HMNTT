All cited code locations are confirmed. Here is the assessment:

---

Audit Report

## Title
Cache Key Collision via `Arrays.hashCode` Allows Cross-Entity Data Leakage in EVM Address Lookup

## Summary
`findByEvmAddressAndDeletedIsFalse()` and `findByEvmAddressOrAliasAndDeletedIsFalse()` in `EntityRepository` use `@spelHelper.hashCode(#alias)` as the sole Caffeine cache key. This resolves to a 32-bit `int` via `Arrays.hashCode(byte[])`. Two distinct byte arrays that produce the same integer hash are indistinguishable at the cache layer, causing the cache to return entity A's data for entity B's address query.

## Finding Description
**Confirmed code locations:**

`EntityRepository.java` lines 32–37 and 39–49 both use `key = "@spelHelper.hashCode(#alias)"` as the sole cache key: [1](#0-0) 

`SpelHelper.java` lines 20–22 confirm `hashCode(byte[])` returns `Arrays.hashCode(value)` — a 32-bit polynomial hash: [2](#0-1) 

The `CaffeineCacheManager` backing both `CACHE_NAME_EVM_ADDRESS` and `CACHE_NAME_ALIAS` stores the autoboxed `Integer` directly as the map key: [3](#0-2) 

**Root cause:** The cache key is the 32-bit output of `Arrays.hashCode`, not the original `byte[]`. Spring's cache abstraction performs no secondary equality check on the original input after a cache hit. Two different `byte[]` inputs with the same `Arrays.hashCode` value are treated as the same key.

**Why `unless = "#result == null"` fails:** This condition only suppresses caching of Java `null`. It provides zero protection against key collisions. Furthermore, since the return type is `Optional<Entity>`, `Optional.empty()` is not `null` and is also cached — meaning a "not found" result for `addrA` can be returned for a valid `addrB` that collides with it. [4](#0-3) 

## Impact Explanation
A caller can receive the full `Entity` record (account ID, balance, keys, type, etc.) of a different entity by querying a crafted colliding address. More critically, this produces incorrect entity resolution during EVM execution — e.g., `eth_call` or `eth_getBalance` resolving the wrong account — which directly corrupts smart contract execution results served by the mirror node. Data correctness is the primary impact; since blockchain entity data is largely public, confidentiality impact is secondary.

## Likelihood Explanation
The report's "birthday attack ~65,536 attempts" framing is imprecise. Targeting a **specific** cached address requires a second-preimage attack against a 32-bit hash, averaging ~2^32 (~4 billion) local `Arrays.hashCode` computations. This is feasible in seconds on modern hardware with no API calls needed to search — only a single API call is needed once the colliding address is found. For a **non-targeted** attack (collide with any of N cached entries), the birthday bound applies: with N=1000 cached entries, expected attempts drop to ~2^32/1000 ≈ 4 million local computations. No credentials, private keys, or privileged access are required.

## Recommendation
Replace the 32-bit `Arrays.hashCode` key with the full byte array encoded as a collision-resistant string. The standard approach is to use a hex or Base64 encoding of the input as the cache key:

```java
key = "T(org.apache.commons.codec.binary.Hex).encodeHexString(#alias)"
// or
key = "T(java.util.HexFormat).of().formatHex(#alias)"
```

Alternatively, add a `hashCode` + `equals`-correct wrapper (e.g., `ByteBuffer.wrap(#alias)` or a `ByteArrayWrapper`) so the cache map performs structural equality on the full byte content, not just the 32-bit hash. The `SpelHelper.hashCode` method should be removed or deprecated to prevent future misuse as a cache key.

## Proof of Concept
```java
// Find addrB such that Arrays.hashCode(addrB) == Arrays.hashCode(addrA)
// addrA = known cached 20-byte EVM address
int targetHash = Arrays.hashCode(addrA);
byte[] addrB = new byte[20];
Random rng = new Random();
do {
    rng.nextBytes(addrB);
} while (Arrays.hashCode(addrB) != targetHash);
// addrB != addrA but produces the same cache key.
// Query findByEvmAddressAndDeletedIsFalse(addrB) → returns entity A's cached record.
```
Expected: ~2^32 iterations on average (~seconds on modern hardware). Once found, a single API call with `addrB` returns entity A's `Entity` record from cache without a database hit.

### Citations

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

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
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
