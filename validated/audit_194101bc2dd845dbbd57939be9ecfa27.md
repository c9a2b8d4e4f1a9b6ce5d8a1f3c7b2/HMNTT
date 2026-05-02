Based on my investigation of the actual code, I can now provide a definitive assessment.

**Verified facts:**

1. `ContractRepository.java` line 16–18: The annotation is exactly as described — `unless = "#result == null"` on a method returning `Optional<byte[]>`. [1](#0-0) 

2. `CacheProperties.java` line 22: The contract cache TTL is `expireAfterAccess=1h` — meaning a poisoned entry persists for 1 hour after the last access (and resets on every access, including by legitimate users). [2](#0-1) 

3. `ContractBytecodeReadableKVState.java` lines 42–46: The caller uses `.orElse(null)` — so a cached `Optional.empty()` propagates as `null` bytecode to the EVM. [3](#0-2) 

4. `EvmConfiguration.java` lines 67–73: The `CACHE_MANAGER_CONTRACT` bean is backed by Caffeine and uses the `CacheProperties.contract` spec. [4](#0-3) 

The bug is real and the exploit flow is accurate. The `unless` guard only blocks caching of a literal `null` return, but Spring Data JPA wraps absent results in `Optional.empty()`, which is non-null, so the guard never fires for the "not found" case.

---

Audit Report

## Title
`findRuntimeBytecode()` Caches `Optional.empty()` Due to Flawed `unless` Condition, Enabling Cache Poisoning via Deployment Race

## Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"`, but the method returns `Optional<byte[]>`. When a contract's `runtime_bytecode` is absent from the database, Spring Data JPA returns `Optional.empty()` — a non-null object. The `unless` condition evaluates to `false`, so the empty Optional is stored in the Caffeine cache under `CACHE_NAME_CONTRACT` keyed by `contractId`. Any caller who queries a contract ID during the importer ingestion lag window poisons the cache for the full access-based TTL (default 1 hour), causing all subsequent EVM simulations for that contract to see no bytecode.

## Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** Spring's `unless` SpEL expression is evaluated against the actual return value. The return type is `Optional<byte[]>`. When no row exists or `runtime_bytecode` is NULL, Spring Data JPA returns `Optional.empty()`. Since `Optional.empty() != null`, the expression `#result == null` evaluates to `false`, the `unless` guard does not fire, and `Optional.empty()` is stored in the Caffeine cache.

**Exploit flow:**
1. A contract is deployed on the Hedera network. The mirror node importer begins ingesting the deployment transaction. Due to normal processing lag, the `entity` row may exist before `contract.runtime_bytecode` is populated.
2. Any user with access to the JSON-RPC endpoint sends an `eth_call` or `eth_estimateGas` request targeting the newly deployed contract's ID before the importer writes `runtime_bytecode`.
3. `findRuntimeBytecode(contractId)` executes the SQL query, finds no bytecode, and returns `Optional.empty()`.
4. Because `Optional.empty() != null`, the `unless` condition is `false`, and `Optional.empty()` is stored in the Caffeine cache keyed by `contractId`.
5. `ContractBytecodeReadableKVState.readFromDataSource()` receives `Optional.empty()`, maps to `null` via `.orElse(null)`, and the EVM treats the contract as having no code.
6. For the entire cache TTL (`expireAfterAccess=1h`), every EVM simulation referencing this `contractId` returns no bytecode — the EVM reverts or executes against empty code. Because the TTL is access-based, every legitimate query resets the expiry, potentially extending the poisoned state indefinitely as long as traffic continues.

**Why the existing check fails:** The `unless` guard was intended to prevent caching of absent results, but it only guards against a literal `null` return. It does not guard against `Optional.empty()`, which is the actual representation of "not found" for this method. The correct expression would be `unless = "#result == null || !#result.isPresent()"`.

## Impact Explanation
All `eth_call`, `eth_estimateGas`, and related EVM simulation requests served by the mirror node's web3 module for the affected contract will return incorrect results (REVERT or wrong execution) for the duration of the cache TTL. Because the cache is `expireAfterAccess`, every incoming request resets the 1-hour window, meaning a moderately trafficked contract could remain poisoned indefinitely. dApps and wallets relying on the mirror node's JSON-RPC for pre-flight simulation will receive false failure signals, potentially blocking user transactions or producing incorrect gas estimates. The mirror node is read-only and does not affect on-chain state directly, so no funds are at direct risk.

## Likelihood Explanation
The Hedera mirror node has a documented ingestion lag between on-chain finality and full DB population. Any user who observes a contract deployment (observable from the public Hedera network or mirror node REST API) can trivially time an `eth_call` to the web3 endpoint within this window. No authentication or special privileges are required. The attack is repeatable: after a cache eviction (e.g., cache size pressure), the attacker can re-poison by issuing another call before the next cache population. The window is narrow but predictable and scriptable. Additionally, the bug can trigger non-maliciously — any legitimate user who happens to query during the ingestion lag will inadvertently poison the cache.

## Recommendation
Change the `unless` condition to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This mirrors the correct pattern that should be applied consistently across all `@Cacheable` methods in the repository layer that return `Optional` types (e.g., `EntityRepository`, `TokenRepository`, `RecordFileRepository`), all of which share the same flawed `unless = "#result == null"` guard.

## Proof of Concept
The existing test `ContractRepositoryTest.findRuntimeBytecodeFailCall` (lines 34–38) confirms that `findRuntimeBytecode` returns `Optional.empty()` for a non-existent contract ID, but does **not** assert that the empty result is excluded from the cache. A reproducing test would:

1. Call `findRuntimeBytecode(nonExistentId)` — returns `Optional.empty()`, gets cached.
2. Insert the contract row with bytecode into the DB.
3. Call `findRuntimeBytecode(nonExistentId)` again — cache hit returns the stale `Optional.empty()` instead of the now-present bytecode.
4. Assert the second call still returns `Optional.empty()` — demonstrating the poisoned cache entry.

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
