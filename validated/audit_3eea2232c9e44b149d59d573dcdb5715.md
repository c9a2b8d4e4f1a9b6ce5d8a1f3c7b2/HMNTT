Let me check the `unless` condition behavior with `Optional` and the cache configuration more carefully.

Based on my thorough review of the code, I can confirm the technical flaw is real and exploitable. Here is my assessment:

---

## Audit Report

## Title
Cache Key Collision via 32-bit `Arrays.hashCode` in `findByEvmAddressAndDeletedIsFalse` Allows Wrong Entity Retrieval

## Summary
`findByEvmAddressAndDeletedIsFalse` and `findByEvmAddressOrAliasAndDeletedIsFalse` in `EntityRepository` use `@spelHelper.hashCode(#alias)` — which resolves to `Arrays.hashCode(byte[])`, a 32-bit signed integer — as the sole Caffeine cache key. Two distinct byte arrays that produce the same `Arrays.hashCode` value will collide in the cache, causing the wrong entity (or a "not found" result) to be returned for a crafted EVM address during `eth_call` / `eth_estimateGas` simulations.

## Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–37: [1](#0-0) 

`common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22: [2](#0-1) 

The SpEL expression `@spelHelper.hashCode(#alias)` evaluates to a 32-bit `int` (autoboxed to `Integer`), which becomes the Caffeine cache key. The cache therefore stores and retrieves entries keyed by `Integer`, not by the actual byte array. Two distinct byte arrays `A` and `B` where `Arrays.hashCode(A) == Arrays.hashCode(B)` share the same cache slot.

**`unless` condition does not prevent caching of empty results:**

`unless = "#result == null"` only skips caching when the Java return value is `null`. The return type is `Optional<Entity>` — both `Optional.empty()` and `Optional.of(entity)` are non-null Java objects and are both cached. This means a cached `Optional.empty()` (entity not found) under key `k` will be returned for any colliding address that actually exists, and vice versa. [1](#0-0) 

**Same pattern in `findByEvmAddressOrAliasAndDeletedIsFalse`:** [3](#0-2) 

**Cache TTL confirmed at 1 second:** [4](#0-3) 

**`CommonEntityAccessor` routes non-long-zero EVM addresses directly to the cached method:** [5](#0-4) 

The `isLongZeroAddress` check only redirects Hedera long-zero addresses (first 12 bytes zero) to an ID-based lookup. Any arbitrary 20-byte EVM address with non-zero prefix reaches `findByEvmAddressAndDeletedIsFalse` and is subject to the collision.

## Impact Explanation
The wrong entity's data (balance, bytecode, account type, keys) is returned for a crafted address during EVM simulation. The mirror node exposes `eth_call` and `eth_estimateGas` via `/api/v1/contracts/call`: [6](#0-5) 

DApps and wallets rely on these endpoints to simulate transactions before submission. A cache collision can cause:
- Incorrect balance reads for a crafted address (returns balance of a different entity)
- Wrong bytecode returned for a crafted contract address, causing simulation to execute against a different contract's logic
- A "not found" result returned for a real entity (if the colliding address was cached first as `Optional.empty()`), causing simulations to fail or behave incorrectly

The `CACHE_NAME_EVM_ADDRESS` cache is shared across all concurrent requests, so a poisoned entry affects every caller until the 1-second TTL expires.

Note: The mirror node is a read-only simulation service and does not write to the blockchain. Claims about actual on-chain fund transfers are not applicable here. The impact is confined to incorrect API simulation results.

## Likelihood Explanation
The attacker requires no privileges — only the ability to submit `eth_call` requests (a standard, permissionless operation). Collision precomputation against `Arrays.hashCode` is offline work: the 32-bit output space means the expected collision cost is ~2^16 trials (birthday bound), trivially achievable on commodity hardware. The 1-second TTL narrows the timing window but does not eliminate the attack: the attacker can automate repeated attempts, and the window resets every time the target entity is re-cached by normal traffic. The attack is repeatable and scriptable.

## Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with the full byte array content. Spring's default `SimpleKeyGenerator` handles `byte[]` arguments by value (using `Arrays.equals` semantics) when the cache key is a `SimpleKey` wrapping the array. The simplest fix is to remove the custom `key` expression entirely and let Spring use the method parameter directly, or use a collision-resistant encoding such as `HexFormat.of().formatHex(#alias)` as the key. The same fix must be applied to `findByEvmAddressOrAliasAndDeletedIsFalse`.

Additionally, consider whether `Optional.empty()` results should be cached at all (negative caching). If not, change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` to prevent caching of "not found" results.

## Proof of Concept
The following demonstrates that two distinct byte arrays can produce the same `Arrays.hashCode` value:

```java
// Arrays.hashCode formula: result = 31 * result + b (for each byte b)
// Find two 20-byte arrays A and B such that Arrays.hashCode(A) == Arrays.hashCode(B)
// With 2^32 possible outputs and 2^160 possible 20-byte inputs,
// birthday collisions are expected after ~2^16 trials.

byte[] target = /* EVM address of target entity T */;
int targetHash = Arrays.hashCode(target);

// Offline brute-force: vary last few bytes of a candidate address
for (int i = 0; i < Integer.MAX_VALUE; i++) {
    byte[] candidate = buildCandidate(i); // 20-byte array, != target
    if (Arrays.hashCode(candidate) == targetHash) {
        // candidate is the colliding address C
        // Step 1: Ensure T is cached (trigger any eth_call to address T)
        // Step 2: Within 1s TTL, submit eth_call to address C
        // Result: findByEvmAddressAndDeletedIsFalse(C) returns entityT from cache
        break;
    }
}
```

The `SpelHelper.hashCode` method confirms the exact hash function used: [2](#0-1)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```
