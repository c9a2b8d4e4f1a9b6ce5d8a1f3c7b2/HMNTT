The code is confirmed. Let me verify the exact behavior of the `ReadableKVStateBase` per-request cache vs. the Caffeine cross-request cache before rendering a verdict.

Key findings from the code:

1. `ContractRepository.findRuntimeBytecode()` — `unless = "#result == null"` with `Optional<byte[]>` return type. `Optional.empty() != null`, so empty results **are** cached. [1](#0-0) 

2. The Caffeine cache manager for `CACHE_MANAGER_CONTRACT` uses `expireAfterAccess=1h` — a **cross-request** persistent cache. [2](#0-1) 

3. `ContractBytecodeReadableKVState.readFromDataSource()` calls `findRuntimeBytecode()` and unwraps with `.orElse(null)`, returning `null` to the EVM when the cached `Optional.empty()` is hit. [3](#0-2) 

4. `ReadableKVStateBase.get()` uses a **per-request** `ContractCallContext`-scoped cache (via `ScopedValue`), which does NOT persist across requests — meaning the Caffeine cache is the only cross-request layer and is the one that gets poisoned. [4](#0-3) 

5. `ContractCallContext.run()` creates a fresh context per call, confirming the per-request cache is not shared. [5](#0-4) 

6. The existing `ContractRepositoryTest` confirms `Optional.empty()` is returned for missing contracts but does **not** test that empty results are excluded from the cache. [6](#0-5) 

The SECURITY.md "Impacts that only require DDoS" exclusion applies to network-level DDoS, not application-level cache poisoning causing incorrect data. This finding is in scope.

---

## Audit Report

## Title
Incorrect `@Cacheable` `unless` Condition Causes `Optional.empty()` to Be Cached, Enabling Stale-Bytecode Poisoning via Race on Contract Deployment

## Summary
`ContractRepository.findRuntimeBytecode()` uses `unless = "#result == null"` to suppress caching of absent results, but the method returns `Optional<byte[]>`. An absent bytecode is represented as `Optional.empty()`, which is a non-null object, so the `unless` guard never fires and the empty result is cached in the Caffeine cross-request cache for up to one hour. A user who queries a newly-deployed contract's bytecode before the importer has committed the `runtime_bytecode` row will poison the cache, causing the mirror node to serve a missing-bytecode record for all subsequent callers until the TTL expires.

## Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

**Root cause:** Spring's `@Cacheable` evaluates `unless` against the actual return value. The return value is `Optional<byte[]>`. When the `contract` table has no row for the given `contractId`, or the row exists but `runtime_bytecode IS NULL`, Spring Data JPA wraps the result in `Optional.empty()`. `Optional.empty() != null`, so `#result == null` is `false`, and the empty Optional is stored in the Caffeine cache under `CACHE_MANAGER_CONTRACT`.

**Cache TTL:** `web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java`, line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [2](#0-1) 

The poisoned entry lives for one hour from last access. Because this is `expireAfterAccess`, repeated queries reset the timer, keeping the entry alive indefinitely.

**Downstream effect:** `ContractBytecodeReadableKVState.readFromDataSource()` calls `findRuntimeBytecode()` and unwraps with `.orElse(null)`, returning `null` to the EVM when the cached `Optional.empty()` is hit:
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
``` [3](#0-2) 

The per-request `ReadableKVStateBase` cache (scoped via `ScopedValue` in `ContractCallContext`) is created fresh per request and does not protect against this — it only deduplicates within a single call execution. [7](#0-6) 

**Why existing checks fail:** The `unless` condition is the only guard against caching absent results. It is semantically wrong for `Optional`-returning methods. There is no secondary validation, no cache invalidation on bytecode insertion, and no TTL short enough to self-heal quickly.

## Impact Explanation
Any `eth_call`, `eth_getCode`, or contract-interaction request routed through the mirror node's web3 service will receive an empty bytecode response for the targeted contract for up to one hour. This causes all EVM simulations against that contract to fail or return incorrect results. Because `expireAfterAccess` resets on every read, a caller who continuously polls the endpoint can keep the poisoned entry alive indefinitely, permanently suppressing correct bytecode responses from the mirror node for that contract ID. Severity: **Medium** (availability/correctness impact on a specific contract, no fund loss, but persistent and operator-invisible without cache inspection).

## Likelihood Explanation
The attack requires no credentials. Contract IDs on Hedera are sequential and predictable; an attacker monitoring the public gossip network or the mirror node's own REST API can learn a contract ID within milliseconds of the `ContractCreate` transaction reaching consensus, before the importer finishes writing the bytecode row. The race window is narrow but repeatable. Additionally, the attack is triggerable without any race at all: querying a not-yet-existing contract ID that will be assigned in the future pre-poisons the cache, so when the bytecode row is eventually committed, the cache already holds `Optional.empty()` for that ID.

## Recommendation
Change the `unless` condition to correctly handle `Optional` return types:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

Or equivalently:
```java
unless = "#result?.isEmpty() ?: true"
```

This ensures that `Optional.empty()` results are never stored in the Caffeine cache, so a subsequent request after the bytecode row is committed will hit the database and return the correct value.

## Proof of Concept

1. Deploy a new contract on Hedera. The importer begins processing the `ContractCreate` record file. The `entity` row is committed first; the `contract` row with `runtime_bytecode` is committed in a subsequent step.
2. During this window, issue an `eth_getCode` or `eth_call` request to the web3 API for the new contract address. This triggers `ContractBytecodeReadableKVState.readFromDataSource()` → `contractRepository.findRuntimeBytecode(entityId.getId())`.
3. The SQL query `select runtime_bytecode from contract where id = :contractId` returns no row (or a null column), so the method returns `Optional.empty()`.
4. Because `Optional.empty() != null`, the `unless` guard does not suppress caching. `Optional.empty()` is stored in the Caffeine cache under `CACHE_NAME_CONTRACT`.
5. The importer finishes committing the `runtime_bytecode` row to the database.
6. All subsequent calls to `findRuntimeBytecode()` for that contract ID hit the Caffeine cache and return `Optional.empty()` — bypassing the database entirely — for up to one hour (or indefinitely if the attacker keeps accessing it, resetting the `expireAfterAccess` timer).
7. `ContractBytecodeReadableKVState.readFromDataSource()` returns `null` (`.orElse(null)`), causing the EVM to treat the contract as having no code, making all `eth_call` and `eth_getCode` requests for that contract return incorrect results.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L78-81)
```java
    public static <T> T run(Function<ContractCallContext, T> function) {
        return ScopedValue.where(SCOPED_VALUE, new ContractCallContext())
                .call(() -> function.apply(SCOPED_VALUE.get()));
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/ContractRepositoryTest.java (L34-38)
```java
    void findRuntimeBytecodeFailCall() {
        Contract contract = domainBuilder.contract().persist();
        long id = contract.getId();
        assertThat(contractRepository.findRuntimeBytecode(++id)).isEmpty();
    }
```
