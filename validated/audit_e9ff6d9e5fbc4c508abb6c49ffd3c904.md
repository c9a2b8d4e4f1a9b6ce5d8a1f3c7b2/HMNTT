#Audit Report

## Title
Negative Cache Poisoning via `Optional.empty()` in `findRuntimeBytecode()` Enables Denial-of-Service for Newly Deployed Contracts

## Summary
The `@Cacheable` guard `unless = "#result == null"` on `ContractRepository.findRuntimeBytecode()` does not account for `Optional.empty()`. Because `Optional.empty()` is a non-null singleton, the SpEL condition evaluates to `false` and the empty result is stored in the Caffeine cache under the queried contract ID. With a 1-hour access-based expiry and no eviction path, an attacker can pre-poison the cache for a predictable future contract ID, causing all subsequent bytecode lookups for that contract to return empty for up to one hour — or indefinitely with periodic re-access.

## Finding Description
**File:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

When the SQL query finds no row, Spring Data JPA returns `Optional.empty()`. This is a non-null Java object, so `#result == null` is `false`, and Spring's caching infrastructure stores the empty `Optional` in the Caffeine cache under the key `contractId`.

**Cache configuration:** `expireAfterAccess=1h,maximumSize=1000,recordStats` [2](#0-1) 

The cache manager is built from this spec with no TTL override: [3](#0-2) 

There is no `@CacheEvict` or any other invalidation path for this cache in the web3 module (confirmed by grep across all web3 Java sources — only `ContractStateServiceImpl` uses eviction, for a different cache).

The consumer of this method is `ContractBytecodeReadableKVState.readFromDataSource()`:

```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);   // Optional.empty() → null → EVM sees no bytecode
``` [4](#0-3) 

The per-request `ReadableKVStateBase` read-cache (backed by `ContractCallContext`) is scoped to a single request and cleared between calls — it does not protect against the persistent Caffeine cache returning a stale empty `Optional` on subsequent requests. [5](#0-4) 

## Impact Explanation
Any newly deployed contract whose entity ID was pre-queried by an attacker becomes unreachable through the mirror node's web3 API. `readFromDataSource()` maps the cached `Optional.empty()` to `null` via `.orElse(null)`, so the EVM sees no bytecode for the contract. Every `eth_call`, `eth_estimateGas`, or contract interaction targeting that contract fails as if the contract does not exist. Because the cache uses `expireAfterAccess`, the attacker can extend the DoS indefinitely by periodically re-querying the same ID, resetting the 1-hour timer. This affects all callers — dApps, wallets, and integrations — that rely on the mirror node for EVM execution.

## Likelihood Explanation
Hedera entity IDs are sequential integers, publicly observable via the mirror node REST API (e.g., `/api/v1/contracts`). An attacker can trivially predict the next contract ID by observing the current highest ID. The trigger requires only a single unauthenticated HTTP request to any web3 endpoint (e.g., `eth_getCode` with the target address). No authentication, special role, or on-chain funds are required. The attack is fully automatable and can be applied to every new contract deployment.

## Recommendation
Change the `unless` condition to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This ensures that only non-empty `Optional` values (i.e., contracts that actually exist with bytecode) are stored in the long-lived Caffeine cache. Absent contracts will always be re-queried from the database on the next request.

## Proof of Concept
1. Observe the current highest contract entity ID `N` via `GET /api/v1/contracts?order=desc&limit=1`.
2. Send `eth_getCode` (or any `eth_call`) targeting the address corresponding to entity ID `N+1` (not yet deployed).
3. `findRuntimeBytecode(N+1)` returns `Optional.empty()` from the DB; `unless = "#result == null"` is `false`; `Optional.empty()` is stored in the Caffeine cache under key `N+1`.
4. Deploy a contract on-chain; the importer writes its bytecode to the `contract` table with ID `N+1`.
5. Send `eth_getCode` for `N+1` again — the Caffeine cache returns the stored `Optional.empty()` without hitting the DB.
6. `readFromDataSource()` returns `null`; the EVM treats the contract as non-existent.
7. All `eth_call` / `eth_estimateGas` calls to contract `N+1` revert or return empty indefinitely.
8. Attacker re-queries `N+1` every ~50 minutes to reset the `expireAfterAccess` timer, extending the DoS indefinitely.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L67-73)
```java
    @Bean(CACHE_MANAGER_CONTRACT)
    CacheManager cacheManagerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME_CONTRACT));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContract());
        return caffeineCacheManager;
    }
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
