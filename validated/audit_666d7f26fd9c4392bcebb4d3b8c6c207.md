Based on my investigation of the actual code, all technical claims check out. Here is my assessment:

---

Audit Report

## Title
Cache Poisoning via Broken `unless` Condition on `Optional` Return Type in `findRuntimeBytecode()`

## Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"` to suppress caching of absent results, but the method returns `Optional<byte[]>`. Because `Optional.empty()` is a non-null object, the guard is permanently inert. Every invocation — including those for non-existent contract IDs — is unconditionally stored in the Caffeine cache. An unprivileged attacker can pre-query a predictable future contract ID, poison the cache with `Optional.empty()`, and cause the mirror node's EVM layer to treat a subsequently deployed contract as having no bytecode for the full cache TTL (default: 1 hour, access-refreshed).

## Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

Spring's SpEL `#result` evaluates to the actual return value of the method. Because the return type is `Optional<byte[]>`, `#result` is always a non-null `Optional` instance. `Optional.empty() == null` evaluates to `false`. The `unless` predicate therefore never fires, and every result — including `Optional.empty()` for a non-existent contract — is stored in the Caffeine cache managed by `CACHE_MANAGER_CONTRACT`.

The cache is configured with `expireAfterAccess=1h,maximumSize=1000` by default: [2](#0-1) 

Because the policy is `expireAfterAccess`, each read of the poisoned entry resets the 1-hour timer, allowing an attacker to keep the stale entry alive indefinitely by periodically re-querying the target ID.

The consumer of this cache, `ContractBytecodeReadableKVState.readFromDataSource()`, calls `.orElse(null)` on the returned `Optional`, so a cached `Optional.empty()` propagates as `null` to the EVM: [3](#0-2) 

No secondary validation, no cache eviction on contract creation, and no fallback DB read exists in this call path.

## Impact Explanation
Any `eth_call`, `eth_estimateGas`, or contract-execution request routed through the mirror node's web3 module that targets the poisoned contract ID will receive a response as if the contract does not exist (empty bytecode → EVM treats address as an EOA or reverts). This is a targeted, repeatable denial-of-service against specific newly deployed contracts. It does not compromise funds directly, but it silently breaks dApp integrations and misleads callers about contract state for up to 1 hour per poisoning event (indefinitely if the attacker refreshes the cache entry).

## Likelihood Explanation
Hedera entity IDs are monotonically increasing integers visible on-chain and via the mirror node REST API. Predicting the next contract ID requires only reading the current highest contract ID — no privileged access is needed. The attack is trivially scriptable: poll for the latest contract ID, immediately query `findRuntimeBytecode(latestId + 1)`, repeat. The window between prediction and deployment is wide enough for automated exploitation.

## Recommendation
Change the `unless` condition to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures that only non-empty `Optional` values (i.e., contracts that actually exist) are stored in the cache, while absent results always fall through to the database on the next call.

## Proof of Concept
1. Query the mirror node REST API to obtain the current highest contract entity ID, e.g., `N`.
2. Send any `eth_call` targeting the long-zero EVM address corresponding to entity ID `N+1` (the predicted next contract). This invokes `findRuntimeBytecode(N+1)`, which returns `Optional.empty()` from the DB and — due to the broken `unless` guard — stores it in the Caffeine cache under key `N+1`.
3. Deploy a contract on Hedera. It receives entity ID `N+1` and its bytecode is written to the `contract` table.
4. Send `eth_call` targeting the same address. `ContractBytecodeReadableKVState.readFromDataSource()` hits the cache, retrieves `Optional.empty()`, calls `.orElse(null)`, and returns `null` to the EVM — the contract appears to have no bytecode.
5. Optionally, repeat step 2 every ~50 minutes to refresh the `expireAfterAccess` timer and extend the poisoning window indefinitely.

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
