All code references check out. Here is the audit result:

---

Audit Report

## Title
Cache Key Collision via `Arrays.hashCode()` Truncation Enables Wrong Entity Return in `CACHE_NAME_EVM_ADDRESS` and `CACHE_NAME_ALIAS`

## Summary
`findByEvmAddressAndDeletedIsFalse()` and `findByEvmAddressOrAliasAndDeletedIsFalse()` use `@spelHelper.hashCode(#alias)` as their Spring `@Cacheable` key. This resolves to `Arrays.hashCode(byte[])`, a 32-bit polynomial hash over a 160-bit (20-byte) EVM address. Because the key space is only 2³², collisions are guaranteed by the pigeonhole principle and are practically findable in milliseconds. A colliding address bypasses the database entirely and receives the cached entity for the original address, with no post-retrieval validation to detect the mismatch.

## Finding Description

**`SpelHelper.hashCode`** returns a plain 32-bit `int`: [1](#0-0) 

This integer is used verbatim as the `@Cacheable` key for both affected methods: [2](#0-1) [3](#0-2) 

Both caches (`CACHE_NAME_EVM_ADDRESS` and `CACHE_NAME_ALIAS`) are registered under the same Caffeine-backed `CACHE_MANAGER_ENTITY`: [4](#0-3) 

After a cache hit, the result is returned directly by `CommonEntityAccessor` with no validation that the returned entity's EVM address matches the queried address: [5](#0-4) 

**Root cause:** A 160-bit input is reduced to a 32-bit cache key. The `unless = "#result == null"` guard only prevents caching of empty results — it does not prevent a cached non-null result from being served to a colliding key.

## Impact Explanation
Any caller querying a colliding address `B` receives the cached entity for address `A`: wrong bytecode, wrong balance, wrong storage. This produces silently incorrect `eth_call` / `eth_estimateGas` results for all users querying `B` for the full TTL of the cache entry. The same flaw applies to alias-based lookups via `CACHE_NAME_ALIAS`. Because the mirror node is a read-only service, no on-chain state is corrupted, but off-chain verification, UI display, and contract simulation results are all affected.

## Likelihood Explanation
The attack requires no credentials and no on-chain transactions — only the ability to send JSON-RPC requests to the public API. Collision search is entirely offline. By the birthday paradox, among ~65,536 candidate 20-byte values, a collision with a target hash is found with ~50% probability. On commodity hardware this completes in milliseconds. The attacker needs only one real entity address, which is trivially obtained from any block explorer. The poisoned cache entry persists for the full configured TTL, serving wrong data to all users during that window.

## Recommendation
Replace the 32-bit hash key with the full byte array (or its hex/Base64 encoding) so that the cache key uniquely identifies the input:

```java
// Instead of:
key = "@spelHelper.hashCode(#alias)"

// Use:
key = "T(java.util.Arrays).toString(#alias)"
// or
key = "T(org.apache.commons.codec.binary.Hex).encodeHexString(#alias)"
```

Alternatively, use the default Spring key (the method argument itself), which uses `Arrays.equals` semantics for byte arrays when wrapped in a `SimpleKey`. Additionally, add a post-retrieval assertion in `CommonEntityAccessor` that the returned entity's `evmAddress` (or `alias`) matches the queried bytes, so a collision is detected and the stale entry is evicted.

## Proof of Concept

```java
// Find two 20-byte arrays with the same Arrays.hashCode
byte[] A = knownEntityEvmAddress; // real entity on Hedera
int targetHash = Arrays.hashCode(A);

// Brute-force B != A such that Arrays.hashCode(B) == targetHash
byte[] B = new byte[20];
Random rng = new Random();
do { rng.nextBytes(B); } while (Arrays.hashCode(B) != targetHash || Arrays.equals(B, A));

// Step 1: Warm cache with A
// GET /api/v1/contracts/call  { "to": "0x" + hex(A), ... }
// -> DB hit, Entity_A stored in cache under key=targetHash

// Step 2: Query with B
// GET /api/v1/contracts/call  { "to": "0x" + hex(B), ... }
// -> Cache hit (key=targetHash), returns Entity_A — wrong entity served
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L66-71)
```java
    public Optional<Entity> getEntityByEvmAddressAndTimestamp(
            final byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
