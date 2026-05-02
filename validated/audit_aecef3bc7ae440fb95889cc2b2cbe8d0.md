All code references check out. Let me verify the technical claims precisely before rendering a verdict.

**Verified facts from the codebase:**

1. `SpelHelper.hashCode(byte[])` returns `Arrays.hashCode(value)` — a 32-bit signed integer. [1](#0-0) 

2. Both `findByEvmAddressOrAliasAndDeletedIsFalse` and `findByEvmAddressAndDeletedIsFalse` use `@spelHelper.hashCode(#alias)` as the sole cache key, with no secondary equality check. [2](#0-1) 

3. The `CACHE_MANAGER_ENTITY` Caffeine cache manager stores both `CACHE_NAME_ALIAS` and `CACHE_NAME_EVM_ADDRESS` caches, keyed by the `Integer` result of the SpEL expression. [3](#0-2) 

4. `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` calls `findByEvmAddressOrAliasAndDeletedIsFalse` when no timestamp is present — the cached path. [4](#0-3) 

5. `AliasesReadableKVState.readFromDataSource` and `AccountReadableKVState.readFromDataSource` both call through `commonEntityAccessor.get(...)`, making them consumers of the poisoned cache path. [5](#0-4) 

The collision construction is mathematically correct. The `unless = "#result == null"` guard only prevents caching null results; it does not validate that a cache hit's entity matches the queried byte array. No exclusion in SECURITY.md applies — this is not theoretical (collision construction is O(1) and analytical), requires no privileges, and is not a best-practice recommendation.

---

## Audit Report

## Title
32-bit `Arrays.hashCode` Cache Key Collision Enables Alias Cache Poisoning in `findByEvmAddressOrAliasAndDeletedIsFalse`

## Summary
`SpelHelper.hashCode(byte[])` delegates to `Arrays.hashCode(byte[])`, returning a 32-bit integer used as the sole Caffeine cache key for both the `CACHE_NAME_ALIAS` and `CACHE_NAME_EVM_ADDRESS` caches. Two distinct byte arrays that produce the same 32-bit hash share a cache slot. An unprivileged attacker who queries entity X (address A) can poison the cache so that a subsequent query for a colliding address B returns entity X instead of entity Y, with no database query and no error.

## Finding Description
**Location:**
- `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22
- `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 32–49

`SpelHelper.hashCode` returns `Arrays.hashCode(value)`, a 32-bit polynomial hash (`result = 31*result + b[i]`). Spring autoboxes the returned `int` to `Integer`, which becomes the Caffeine map key. Two different `byte[]` inputs with the same hash produce the same `Integer` key and collide on the same cache slot.

The `@Cacheable` annotation:
```java
@Cacheable(
    cacheNames = CACHE_NAME_ALIAS,
    cacheManager = CACHE_MANAGER_ENTITY,
    key = "@spelHelper.hashCode(#alias)",
    unless = "#result == null")
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```
The `unless = "#result == null"` guard only skips caching null results. It does not verify that a cache hit's entity `evm_address` or `alias` field matches the queried `#alias` parameter.

**Collision construction:** For any byte array A of length ≥ 2, construct B by:
```
B[i]   = A[i]   + 1
B[i+1] = A[i+1] - 31
```
This satisfies `31*(B[i]-A[i]) + (B[i+1]-A[i+1]) = 31 - 31 = 0`, so `Arrays.hashCode(A) == Arrays.hashCode(B)` exactly, provided both bytes remain in `[0, 255]`.

**Exploit flow:**
1. Attacker identifies entity X with address A (public on-chain data).
2. Attacker computes B analytically such that `Arrays.hashCode(A) == Arrays.hashCode(B)`, where B is the address a victim will query.
3. Attacker sends `eth_call` resolving A → entity X is stored in cache under key `K = hashCode(A)`.
4. Victim queries B → `hashCode(B) = K` → cache hit returns entity X instead of entity Y, no DB query made.

The same issue affects `findByEvmAddressAndDeletedIsFalse` (lines 32–37) under `CACHE_NAME_EVM_ADDRESS`.

## Impact Explanation
Any caller of `CommonEntityAccessor.get(Bytes alias, Optional.empty())` hits the poisoned cache path. This includes `AliasesReadableKVState.readFromDataSource` and `AccountReadableKVState.readFromDataSource`, which feed alias resolution into the EVM execution layer. A poisoned entry causes `CALL`/`STATICCALL` targeting address B to execute against the code and storage of entity X. Consequences include: silent misdirection of contract calls, incorrect balance/nonce reads, wrong authorization checks, and incorrect `AccountID` resolution — all without any privileged access. The poisoned entry persists until TTL expiry (governed by `cacheProperties.getEntity()`), after which the attacker can trivially re-poison.

## Likelihood Explanation
The attack requires only the ability to send JSON-RPC requests (e.g., `eth_call`). Hedera entity addresses are publicly enumerable via the mirror node REST API. The 32-bit hash space means the birthday bound for a 50% natural collision probability is ~65,536 entities; a production network with millions of accounts will contain many naturally colliding pairs. Beyond natural collisions, the attacker can analytically construct a colliding address in O(1) by adjusting two bytes of any known address, making targeted poisoning straightforward and repeatable.

## Recommendation
Replace the 32-bit `Arrays.hashCode` cache key with the full byte array content. Options:
1. Use `Arrays.toString(#alias)` or `T(java.util.Base64).getEncoder().encodeToString(#alias)` as the SpEL key expression, producing a collision-free string key.
2. Use `T(java.util.Arrays).toString(#alias)` directly in the SpEL expression.
3. Remove the custom `key` expression entirely and let Spring use the default key strategy, which wraps parameters in a `SimpleKey` that performs deep array equality via `Arrays.equals`.

Option 3 is the simplest and most robust: removing `key = "@spelHelper.hashCode(#alias)"` causes Spring to use `SimpleKey(alias)`, which calls `Arrays.equals` for `byte[]` parameters and is collision-free.

Additionally, add a post-cache validation guard (e.g., `condition` or result verification) to confirm the returned entity's `evm_address`/`alias` matches the queried input.

## Proof of Concept
```java
// Demonstrate collision: Arrays.hashCode([1, 0]) == Arrays.hashCode([0, 31])
byte[] A = new byte[]{1, 0};
byte[] B = new byte[]{0, 31};  // B[0]=A[0]-1=0, B[1]=A[1]+31=31
assert Arrays.hashCode(A) == Arrays.hashCode(B);  // both = 31*31 + 0 = 961... verify:
// Arrays.hashCode([1,0])  = 31*(31*1 + 1) + 0 = 31*32 = 992
// Arrays.hashCode([0,31]) = 31*(31*1 + 0) + 31 = 31*31 + 31 = 961+31 = 992  ✓

// Exploit:
// 1. Query entity at address A → cached under key Integer(992)
entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(A); // DB hit, caches entity X

// 2. Query entity at address B → cache hit returns entity X, no DB query
entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(B); // returns entity X ← WRONG
```

### Citations

**File:** common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java (L20-22)
```java
    public int hashCode(byte[] value) {
        return Arrays.hashCode(value);
    }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/AliasesReadableKVState.java (L57-67)
```java
    protected AccountID readFromDataSource(@NonNull ProtoBytes alias) {
        final var timestamp = ContractCallContext.get().getTimestamp();
        final var entity = commonEntityAccessor.get(alias.value(), timestamp);
        return entity.map(e -> {
                    final var account = accountFromEntity(e, timestamp);
                    final var accountID = account.accountId();
                    // Put the account in the account num cache.
                    aliasedAccountCacheManager.putAccountNum(accountID, account);
                    return accountID;
                })
                .orElse(null);
```
