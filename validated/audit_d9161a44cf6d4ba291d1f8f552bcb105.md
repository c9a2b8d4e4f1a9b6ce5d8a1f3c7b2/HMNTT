After verifying all referenced code paths in the repository, the claim is technically accurate. Here is the audit report:

---

Audit Report

## Title
32-bit `Arrays.hashCode` Cache Key Collision in `CACHE_NAME_EVM_ADDRESS` Allows Wrong Entity Served for Distinct EVM Addresses

## Summary
`findByEvmAddressAndDeletedIsFalse` uses `@spelHelper.hashCode(#alias)` — a 32-bit `Arrays.hashCode(byte[])` — as the **sole** cache key for `CACHE_NAME_EVM_ADDRESS`. Two distinct 20-byte EVM addresses that produce the same 32-bit hash will share a cache entry, causing the mirror node to return the wrong entity's data for all subsequent lookups of the colliding address.

## Finding Description

**`SpelHelper.hashCode` delegates directly to `Arrays.hashCode(byte[])`**, returning a signed 32-bit `int`: [1](#0-0) 

This 32-bit integer is used as the **sole cache key** for `CACHE_NAME_EVM_ADDRESS`: [2](#0-1) 

Spring's `@Cacheable` performs no secondary validation — it returns the cached `Optional<Entity>` directly when the key matches, regardless of whether the stored entity's actual EVM address matches the queried `alias`. The `unless = "#result == null"` guard only prevents caching of empty results; it does not re-validate a stored value against a new input.

The `CACHE_NAME_EVM_ADDRESS` and `CACHE_NAME_ALIAS` caches are both registered under the same `CACHE_MANAGER_ENTITY` bean: [3](#0-2) 

The live (non-historical) EVM execution path calls `findByEvmAddressAndDeletedIsFalse` via `getEntityByEvmAddressTimestamp` when no block timestamp is provided: [4](#0-3) 

This is reached from the public `get(Address, Optional<Long>)` entry point for any non-long-zero address: [5](#0-4) 

**Root cause:** `Arrays.hashCode(byte[])` computes a 32-bit polynomial hash over 20-byte (160-bit) inputs. The output space is 2^32 while the input space is 2^160, making collisions analytically constructible. For any address A with bytes `[..., a18, a19]`, address B `[..., a18+1, a19-31]` produces an identical hash (the contribution change is `31×(+1) + (−31) = 0`). No brute force is required for the algebraic case; for the CREATE2 case, ~2^32 off-chain address computations (milliseconds on modern hardware) suffice to find a colliding address.

## Impact Explanation
Once entity A is cached under key `hashCode(A)`, any lookup for address B where `hashCode(B) == hashCode(A)` returns A's entity data without a database query. Downstream EVM execution operates on the wrong entity: wrong contract bytecode may be executed, wrong balances returned, wrong account type used for permission checks. Every mirror node instance that has cached the poisoned entry serves incorrect state for all subsequent callers of address B until the cache expires. The Caffeine cache is per-instance in-memory, so all instances receiving traffic for address A are independently poisoned.

## Likelihood Explanation
No privileged access is required. An attacker needs only:
1. The ability to create a Hedera account (ECDSA key) or deploy a contract — both are standard unprivileged operations.
2. Knowledge of a target address B (publicly observable on-chain).
3. Off-chain iteration (~2^32 key-pair or CREATE2 address computations, feasible in seconds) to find an address A with `hashCode(A) == hashCode(B)`, followed by a single on-chain transaction to register entity A.
4. One query to the mirror node for address A to populate the cache.

The hash function is public, deterministic, and has no secret component. The attack is repeatable and scriptable.

## Recommendation
Replace the 32-bit hash with the full byte-array as the cache key. Spring's `@Cacheable` supports `byte[]` keys natively via `Arrays.equals`/`Arrays.hashCode` in `SimpleKey`, or a custom `KeyGenerator` can serialize the byte array to a hex string:

```java
key = "T(org.bouncycastle.util.encoders.Hex).toHexString(#alias)"
// or simply omit the key attribute and let Spring use the full byte[] parameter
```

This eliminates the collision surface entirely. The same fix applies to `findByEvmAddressOrAliasAndDeletedIsFalse`, which has the identical pattern: [6](#0-5) 

## Proof of Concept

```
Target address B = [b0, b1, ..., b17, b18, b19]

Construct colliding address A:
  A = [b0, b1, ..., b17, (b18 + 1) & 0xFF, (b19 - 31) & 0xFF]

Verify: Arrays.hashCode(A) == Arrays.hashCode(B)
  Δhash = 31 * ((b18+1) - b18) + ((b19-31) - b19)
        = 31 * 1 + (-31) = 0  ✓

Attack steps:
1. Register entity A on Hedera (one account creation or CREATE2 deploy).
2. Query mirror node: GET /api/v1/contracts/call with `to` = hex(A).
   → Cache entry [hashCode(A)] = Entity{A} is stored.
3. Query mirror node: GET /api/v1/contracts/call with `to` = hex(B).
   → Cache hit on key hashCode(B) == hashCode(A) → returns Entity{A}.
   → EVM executes with A's bytecode/balance/type instead of B's.
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L39-43)
```java
    @Cacheable(
            cacheNames = CACHE_NAME_ALIAS,
            cacheManager = CACHE_MANAGER_ENTITY,
            key = "@spelHelper.hashCode(#alias)",
            unless = "#result == null")
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L29-36)
```java
    public @NonNull Optional<Entity> get(@NonNull final Address address, final Optional<Long> timestamp) {
        final var addressBytes = address.toArrayUnsafe();
        if (ConversionUtils.isLongZeroAddress(addressBytes)) {
            return getEntityByMirrorAddressAndTimestamp(address, timestamp);
        } else {
            return getEntityByEvmAddressTimestamp(address.toArrayUnsafe(), timestamp);
        }
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
