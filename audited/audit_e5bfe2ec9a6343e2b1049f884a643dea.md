### Title
32-bit `Arrays.hashCode` Cache Key Collision Enables Alias Cache Poisoning in `findByEvmAddressOrAliasAndDeletedIsFalse`

### Summary
`SpelHelper.hashCode(byte[] value)` delegates to `Arrays.hashCode(value)`, producing a 32-bit integer used as the sole cache key for `CACHE_NAME_ALIAS`. Two distinct byte-array aliases that produce the same 32-bit hash will map to the same cache slot. An attacker who registers an account whose alias collides with a fee-collecting entity's alias can poison the cache so that subsequent lookups for the fee collector return the attacker's entity instead, causing incorrect fee-collector resolution during EVM execution.

### Finding Description

**Exact code location:**
- `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java`, lines 39–49
- `common/src/main/java/org/hiero/mirror/common/util/SpelHelper.java`, lines 20–22

**Root cause:**

`SpelHelper.hashCode` returns `Arrays.hashCode(value)`, a 32-bit polynomial hash:

```
result = 1
for each byte b: result = 31 * result + (b & 0xFF)
```

This value is used verbatim as the Caffeine cache key:

```java
@Cacheable(
    cacheNames = CACHE_NAME_ALIAS,
    cacheManager = CACHE_MANAGER_ENTITY,
    key = "@spelHelper.hashCode(#alias)",   // ← 32-bit int only
    unless = "#result == null")
Optional<Entity> findByEvmAddressOrAliasAndDeletedIsFalse(byte[] alias);
```

The cache manager is configured at `EvmConfiguration.cacheManagerEntity()` (line 99–105), which shares the same Caffeine spec (`expireAfterWrite=1s,maximumSize=10000`) for `CACHE_NAME`, `CACHE_NAME_EVM_ADDRESS`, and `CACHE_NAME_ALIAS`.

**Exploit flow:**

1. Attacker identifies target fee-collecting entity with alias `A` (e.g., a 20-byte EVM address).
2. Attacker brute-forces an alias `B ≠ A` such that `Arrays.hashCode(B) == Arrays.hashCode(A)`. The 32-bit output space makes this feasible: expected ~2³² iterations, achievable in seconds–minutes on commodity hardware.
3. Attacker registers an account on the Hedera network with alias `B` (requires paying a small network fee).
4. Attacker submits a contract call that causes the mirror node to invoke `findByEvmAddressOrAliasAndDeletedIsFalse(B)`. This hits the DB, returns entity B, and stores it in `CACHE_NAME_ALIAS` under key `hash(B) = hash(A)`.
5. Within the same 1-second TTL window, any call that resolves the fee-collecting entity by alias `A` receives entity B from cache without a DB round-trip.
6. `CommonEntityAccessor.get(Bytes alias, Optional<Long> timestamp)` (line 46–50) returns entity B for alias A.

**Why existing checks fail:**

- `unless = "#result == null"` only prevents caching empty results; it does not validate that the cached entity's alias actually matches the lookup key.
- There is no post-cache equality check comparing the returned entity's `evm_address`/`alias` field against the requested byte array.
- The Caffeine cache itself performs no key equality beyond the integer hash.

### Impact Explanation

When a fee-collecting entity is resolved by alias during EVM execution (e.g., via `TokenReadableKVState.mapFixedFees` → `commonEntityAccessor.get(collectorAccountId, timestamp)` for alias-addressed collectors, or directly in contract calls referencing the collector by EVM address), the wrong entity is returned. Consequences include:

- Custom fee amounts computed against the wrong entity's parameters (e.g., `allCollectorsAreExempt` flag of entity B applied instead of entity A), causing fees to be undercharged or exempted outside design parameters.
- Fee revenue directed to the wrong account for the duration of the poisoned cache window.

Severity is **medium**: the window is bounded by the 1-second TTL, but the attacker can continuously re-trigger the poisoning request to sustain the effect across many transactions.

### Likelihood Explanation

- **Unprivileged**: No special role is required. Any Hedera account holder can submit contract calls and register accounts.
- **Computational cost**: Finding a 32-bit `Arrays.hashCode` preimage for a 20-byte target requires ~2³² hash evaluations (~4 billion), achievable in under a minute on a GPU or a few minutes on a CPU.
- **On-chain cost**: Registering the colliding account costs a small HBAR fee (fractions of a cent at typical prices), making the attack economically viable.
- **Repeatability**: The attacker must re-poison every ~1 second due to the TTL, but a single automated script can sustain this indefinitely.
- **Targeting**: The attacker must know the target fee collector's alias bytes, which are publicly visible on-chain.

Overall likelihood: **low-medium** — technically feasible for a motivated attacker, but requires upfront computation and continuous re-triggering.

### Recommendation

Replace the 32-bit hash key with a collision-resistant representation of the full byte array. Options:

1. Use `T(java.util.Arrays).toString(#alias)` as the SpEL key expression — this produces a unique string per distinct byte array with no collision risk.
2. Use a hex-encoded string: `T(org.apache.commons.codec.binary.Hex).encodeHexString(#alias)`.
3. Wrap the byte array in a value object that implements `equals`/`hashCode` correctly (e.g., `ByteBuffer.wrap(alias)`) and use it as the key.

Additionally, add a post-cache validation step that confirms the returned entity's `evm_address` or `alias` field matches the requested bytes before returning it to the caller.

### Proof of Concept

```java
// Step 1: Find collision offline
byte[] targetAlias = feeCollectorEntity.getAlias(); // known from chain
int targetHash = Arrays.hashCode(targetAlias);

byte[] colliderAlias = new byte[20];
for (long i = 0; i < 0xFFFFFFFFL; i++) {
    // fill colliderAlias with bytes derived from i
    ByteBuffer.wrap(colliderAlias).putLong(i).putLong(i).putInt((int)i);
    if (Arrays.hashCode(colliderAlias) == targetHash) break; // found
}

// Step 2: Register Hedera account with alias = colliderAlias (standard AccountCreate tx)

// Step 3: Continuously submit eth_call referencing colliderAlias to poison cache
// Each call triggers: findByEvmAddressOrAliasAndDeletedIsFalse(colliderAlias)
// → DB returns attacker's entity → stored at key targetHash

// Step 4: Concurrent legitimate call for targetAlias hits cache key targetHash
// → returns attacker's entity instead of fee collector
// → fee parameters (allCollectorsAreExempt, collectorAccountId) are wrong
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-33)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";

    @NotBlank
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";

    @NotBlank
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";

    @NotBlank
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";

    private boolean enableBatchContractSlotCaching = true;

    @NotBlank
    private String entity = ENTITY_CACHE_CONFIG;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/CommonEntityAccessor.java (L46-50)
```java
    public @NonNull Optional<Entity> get(@NonNull final Bytes alias, final Optional<Long> timestamp) {
        return timestamp
                .map(t -> entityRepository.findActiveByEvmAddressOrAliasAndTimestamp(alias.toByteArray(), t))
                .orElseGet(() -> entityRepository.findByEvmAddressOrAliasAndDeletedIsFalse(alias.toByteArray()));
    }
```
