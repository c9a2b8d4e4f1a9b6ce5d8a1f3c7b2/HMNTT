All code references check out. Here is the assessment:

---

Audit Report

## Title
Cache Key Collision via 32-bit `Arrays.hashCode` on 20-byte EVM Address Enables Entity Data Substitution in `CACHE_NAME_EVM_ADDRESS`

## Summary
`findByEvmAddressAndDeletedIsFalse` and `findByEvmAddressOrAliasAndDeletedIsFalse` in `EntityRepository` use a 32-bit `int` from `Arrays.hashCode(byte[])` as the sole Caffeine cache key for 20-byte EVM addresses. Two distinct addresses that produce the same hash integer are treated as identical cache keys, allowing an attacker to poison the cache so that queries for one address return another entity's data. The `unless = "#result == null"` guard is structurally inert because the return type is `Optional<Entity>`, which is never `null`.

## Finding Description

**Exact code path — cache annotation:**

`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–37: [1](#0-0) 

The `key` expression `@spelHelper.hashCode(#alias)` delegates to:

`common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22: [2](#0-1) 

`Arrays.hashCode(byte[])` computes a polynomial rolling hash modulo 2^32, returning a Java `int`. This 32-bit integer is the **sole** cache key. Spring's `CaffeineCacheManager` stores and retrieves entries using `Integer.equals()` on this key — no secondary equality check on the actual byte array is performed.

The same flaw exists identically on `findByEvmAddressOrAliasAndDeletedIsFalse` at lines 39–49: [3](#0-2) 

**`unless = "#result == null"` is inert:**
Both methods return `Optional<Entity>`. In Spring Cache SpEL, `#result` is the `Optional` wrapper object, which is **never** `null` — it is either `Optional.empty()` or `Optional.of(entity)`. The condition `#result == null` is always `false`, so every result, including `Optional.empty()`, is unconditionally cached. This means an attacker can also cache `Optional.empty()` under a colliding key to make a real entity appear non-existent.

**Cache TTL:**
The entity cache is configured with `expireAfterWrite=1s,maximumSize=10000`: [4](#0-3) 

This applies to the `CACHE_MANAGER_ENTITY` bean, which registers both `CACHE_NAME_EVM_ADDRESS` and `CACHE_NAME_ALIAS`: [5](#0-4) 

**Call path to the vulnerable method:**
`CommonEntityAccessor.getEntityByEvmAddressTimestamp` (called for all non-long-zero EVM address lookups) routes to `findByEvmAddressAndDeletedIsFalse` when no historical timestamp is present: [6](#0-5) 

## Impact Explanation

When the cache is poisoned, `eth_call` and `eth_estimateGas` requests targeting victim address B receive entity A's data (balance, type, bytecode pointer, key). Concrete consequences:

- **Wrong balance**: EVM simulation for B uses A's balance, causing balance-check calls to return incorrect values.
- **Wrong entity type**: If A is a contract and B is an account (or vice versa), the EVM simulation uses the wrong code/type, causing calls to revert or behave incorrectly.
- **Wrong gas estimates**: `eth_estimateGas` for transactions targeting B returns estimates based on A's state, potentially causing submitted transactions to fail with out-of-gas.
- **Entity erasure**: If A does not exist, `Optional.empty()` is cached under the collision key (because `unless = "#result == null"` never fires), making B appear non-existent to all callers within the TTL window.

This affects the read/simulation layer of the mirror node. DApps and wallets relying on `eth_call`/`eth_estimateGas` for pre-flight checks will receive corrupted data, leading to failed transactions, incorrect UI state, and potential financial miscalculation in DeFi contexts.

## Likelihood Explanation

- **Permissionless**: No privileged access required. Any Hedera user can create accounts.
- **Computationally feasible**: A preimage attack on `Arrays.hashCode` over 20-byte inputs requires ~2^32 ≈ 4.3 billion hash evaluations. At ~500M evaluations/second on a single CPU core, this completes in under 10 seconds. GPU acceleration reduces this further.
- **Repeatable**: After the 1-second TTL expires, the attacker can re-poison the cache. The attack can be sustained continuously with minimal cost.
- **Targeted**: The attacker selects a specific victim address B, making this a targeted rather than opportunistic attack.

## Recommendation

1. **Replace the hash-based key with the full byte array.** Use the raw `byte[]` (or its hex/Base64 encoding) as the cache key so that Spring's key equality check is performed on the full 20-byte address, not a 32-bit projection:
   ```java
   key = "T(java.util.Arrays).toString(#alias)"
   // or
   key = "T(org.bouncycastle.util.encoders.Hex).toHexString(#alias)"
   ```
   This eliminates the collision surface entirely.

2. **Fix the `unless` guard.** Change `unless = "#result == null"` to `unless = "#result != null && !#result.isPresent()"` (or `unless = "#result?.isEmpty() == true"`) to correctly prevent caching of empty Optionals if that is the intended behavior. If caching negative results is intentional, document it explicitly.

3. **Apply the same fix to `findByEvmAddressOrAliasAndDeletedIsFalse`** (lines 39–49), which has the identical flaw.

## Proof of Concept

```java
// Offline: find a collision for target address B_addr
byte[] B_addr = ...; // victim's known EVM address
int targetHash = Arrays.hashCode(B_addr);

// Generate ECDSA key pairs, derive EVM address A_addr = keccak256(pubkey)[12:]
// until Arrays.hashCode(A_addr) == targetHash
// Expected trials: ~2^32 ≈ 4.3 billion; ~8 seconds on a single CPU core

// On-chain: create a Hedera account with the matching key pair (~$0.05)
// Entity A now exists in the mirror node DB with address A_addr

// Step 1: Poison the cache
// Send eth_call for A_addr → findByEvmAddressAndDeletedIsFalse(A_addr) executes,
// returns Optional.of(entityA), stored under key=targetHash

// Step 2: Within the 1-second TTL window, any request for B_addr
// → findByEvmAddressAndDeletedIsFalse(B_addr) computes hashCode(B_addr)==targetHash
// → cache HIT → returns Optional.of(entityA) instead of entityB

// Entity erasure variant: if A_addr does not exist in DB,
// Optional.empty() is cached under targetHash (because unless="#result==null" never fires),
// making B appear non-existent for the TTL window.
```

### Citations

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

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-19)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L80-84)
```java
    private Optional<Entity> getEntityByEvmAddressTimestamp(byte[] addressBytes, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressAndTimestamp(addressBytes, t))
                .orElseGet(() -> entityRepository.findByEvmAddressAndDeletedIsFalse(addressBytes));
    }
```
