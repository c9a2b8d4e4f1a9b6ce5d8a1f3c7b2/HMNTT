All referenced code is confirmed in the repository. Let me verify the technical claims precisely before rendering a verdict.

**Verified facts:**

1. `ContractRepository.findRuntimeBytecode()` at line 16 uses `unless = "#result == null"` with return type `Optional<byte[]>` — confirmed. [1](#0-0) 

2. `CacheProperties.contract` defaults to `expireAfterAccess=1h` — confirmed. [2](#0-1) 

3. `ContractBytecodeReadableKVState.readFromDataSource()` calls `.orElse(null)` on the result — confirmed. [3](#0-2) 

4. `ReadableKVStateBase.get()` uses a **per-request** `ContractCallContext` cache, not a persistent one. The Spring/Caffeine cache is the only persistent layer. [4](#0-3) [5](#0-4) 

The root cause is confirmed: `Optional.empty()` is a non-null singleton, so `#result == null` evaluates to `false` for a "not found" DB result, and the empty Optional is stored in the Caffeine cache for up to 1 hour.

---

## Audit Report

## Title
Negative-Result Cache Poisoning in `findRuntimeBytecode()` Allows DoS on Newly Deployed Contracts

## Summary
`ContractRepository.findRuntimeBytecode()` is annotated with `@Cacheable(unless = "#result == null")` but returns `Optional<byte[]>`. When a contract does not exist in the database, the method returns `Optional.empty()` — a non-null object — which bypasses the `unless` guard and is stored in the Caffeine cache with a TTL of up to 1 hour (`expireAfterAccess=1h`). An attacker who can predict a future contract's sequential Hedera entity ID can pre-populate this cache entry before the contract is deployed, causing the EVM to treat the newly deployed contract as non-existent for the full cache lifetime.

## Finding Description

**Root cause:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

Spring's `unless` SpEL expression `"#result == null"` evaluates to `false` when the result is `Optional.empty()`, because `Optional.empty()` is a non-null singleton in Java. The intent was to avoid caching "not found" results, but the condition only guards against a literal `null` return. Since the method signature returns `Optional<byte[]>`, a missing contract produces `Optional.empty()`, which is unconditionally stored in the Caffeine cache.

**Cache configuration** (`CacheProperties.java`, line 22):
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [2](#0-1) 

`expireAfterAccess=1h` means the poisoned entry survives for 1 hour from the last access. Repeated attacker queries reset the timer, potentially extending the window indefinitely.

**Downstream propagation:**

`ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode(entityId.getId())` and terminates with `.orElse(null)`:
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
``` [3](#0-2) 

When the Spring cache returns the poisoned `Optional.empty()`, `.orElse(null)` returns `null`, and the EVM interprets `null` bytecode as a non-existent contract.

**Why the per-request cache does not help:**

`ReadableKVStateBase.get()` uses a per-request `ContractCallContext` cache that is cleared between requests. It calls `readFromDataSource()` on every new request for a key not yet seen in that request's context, which then hits the persistent Spring/Caffeine cache. [4](#0-3) [5](#0-4) 

There is no secondary validation that bypasses the Spring cache and re-queries the DB.

## Impact Explanation
Any contract deployed at a predictable entity ID can be rendered invisible to the EVM for up to 1 hour (or indefinitely if the attacker keeps refreshing the cache entry via repeated read-only calls). All `eth_call`, `eth_estimateGas`, and internal EVM `CALL`/`STATICCALL` operations targeting the contract will fail as if the contract does not exist. This is a targeted, repeatable denial-of-service against specific contracts with no cost beyond submitting unauthenticated read-only API calls.

## Likelihood Explanation
Hedera entity IDs are strictly sequential and publicly observable via the mirror node REST API and on-chain receipts. No privileged access, private keys, or gas is required — only unauthenticated read-only `eth_call` requests. The attack is trivially scriptable: poll the current max entity ID, fire a pre-poisoning call, and repeat to keep the cache warm.

## Recommendation
Change the `unless` condition to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

Alternatively, change the return type to `byte[]` (returning `null` when not found) and keep the existing `unless = "#result == null"` guard, which would then correctly prevent caching of absent results.

## Proof of Concept
1. Query the mirror node REST API (e.g., `GET /api/v1/entities?order=desc&limit=1`) to obtain the current highest entity ID `N`.
2. Predict the next contract entity ID as `X = N + 1` (or a small offset).
3. Submit an `eth_call` to the mirror node web3 API targeting address `X` (long-zero EVM address `0x000...0X`). Since no contract exists yet, `findRuntimeBytecode(X)` queries the DB, gets no row, returns `Optional.empty()`, and Spring caches it under key `X`.
4. Deploy a contract on Hedera; it receives entity ID `X`.
5. Submit any `eth_call` targeting `X`. `findRuntimeBytecode(X)` returns the cached `Optional.empty()` without hitting the DB. `readFromDataSource()` returns `null`. The EVM treats `X` as a non-existent account; all calls revert or behave as EOA calls.
6. Repeat step 3 every ~59 minutes to reset the `expireAfterAccess` timer and extend the disruption window indefinitely.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java (L16-18)
```java
    @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
    @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
    Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L22-22)
```java
    private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L42-46)
```java
        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
```

**File:** web3/src/main/java/com/swirlds/state/spi/ReadableKVStateBase.java (L60-69)
```java
    public V get(@NonNull K key) {
        // We need to cache the item because somebody may perform business logic basic on this
        // contains call, even if they never need the value itself!
        Objects.requireNonNull(key);
        if (!hasBeenRead(key)) {
            final var value = readFromDataSource(key);
            markRead(key, value);
        }
        final var value = getReadCache().get(key);
        return (value == marker) ? null : (V) value;
```

**File:** web3/src/main/java/com/swirlds/state/spi/ReadableKVStateBase.java (L121-123)
```java
    private Map<Object, Object> getReadCache() {
        return ContractCallContext.get().getReadCacheState(getStateId());
    }
```
