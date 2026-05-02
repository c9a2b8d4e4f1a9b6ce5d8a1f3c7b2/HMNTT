All code references verified. Here is the assessment:

---

Audit Report

## Title
`Optional.empty()` Incorrectly Cached by `findRuntimeBytecode()` Due to Insufficient `unless` Condition Causes Persistent Missing Bytecode Responses

## Summary
`ContractRepository.findRuntimeBytecode()` is annotated with `@Cacheable(unless = "#result == null")`. Because the method returns `Optional<byte[]>`, the return value is **never** a literal Java `null` — it is either `Optional.of(bytes)` or `Optional.empty()`. The `unless` condition therefore never fires for the empty case, causing `Optional.empty()` to be stored in the Caffeine cache with a TTL of `expireAfterAccess=1h`. Any caller that queries a contract ID before its `runtime_bytecode` is available will receive a cached empty result for up to one hour, or indefinitely if the same ID is periodically re-queried.

## Finding Description

**Exact location:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

Spring's `@Cacheable` `unless` SpEL expression `"#result == null"` only suppresses caching when the method returns a literal Java `null`. Since the return type is `Optional<byte[]>`, the JPA/native query layer wraps absent or NULL DB results in `Optional.empty()` — a non-null object — so the condition evaluates to `false` and the empty Optional **is stored in the cache**.

**Cache TTL:**

`web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java`, line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [2](#0-1) 

`expireAfterAccess` means the TTL resets on every read. A caller that periodically re-queries the same contract ID will keep the stale `Optional.empty()` entry alive indefinitely.

**Two-phase write window:**

`SidecarContractMigration.migrate()` in `importer/src/main/java/org/hiero/mirror/importer/migration/SidecarContractMigration.java` performs an `INSERT … ON CONFLICT DO UPDATE SET runtime_bytecode = …` as a raw JDBC batch operation (lines 44–48), separate from the entity row creation performed by the entity listener. [3](#0-2) 

This migration is invoked from `ContractResultServiceImpl.processSidecarRecords()` at line 425, after sidecar records are iterated — meaning the contract entity row can be committed to the DB before `runtime_bytecode` is populated. [4](#0-3) 

**Downstream effect:**

`ContractBytecodeReadableKVState.readFromDataSource()` maps the result directly:
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
``` [5](#0-4) 

A cached `Optional.empty()` causes `.orElse(null)` to return `null`, which the EVM layer treats as a non-existent contract.

## Impact Explanation
Any `eth_getCode` call, EVM simulation (`eth_call`, `eth_estimateGas`), or contract-call that relies on bytecode lookup for the targeted contract will receive an empty/zero response for up to 1 hour after the first empty-result query, or longer if the entry is kept alive by periodic re-queries. Downstream integrations — block explorers, DeFi protocols, contract verifiers — will incorrectly treat a legitimately deployed contract as non-existent or undeployed for the duration of the cache entry's lifetime.

## Likelihood Explanation
No privileges are required. The trigger condition (querying a contract ID before its `runtime_bytecode` is written) can occur naturally during normal indexing lag, or can be deliberately targeted: contract IDs are visible in transaction records immediately after submission, and the deployment-to-sidecar-write window spans at least one record file processing interval. The attack is repeatable for every new contract deployment and requires only a standard JSON-RPC `eth_getCode` or equivalent call. The `expireAfterAccess` policy means a single automated re-query every ~59 minutes is sufficient to keep the stale entry alive indefinitely.

## Recommendation
Change the `unless` condition to explicitly exclude `Optional.empty()`:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures only non-empty `Optional` values (i.e., contracts with actual bytecode) are cached, while absent/null results are always re-fetched from the database on the next call.

## Proof of Concept
1. Deploy a contract on Hedera. The contract entity row is committed to the DB.
2. Before `SidecarContractMigration.migrate()` completes (i.e., before `runtime_bytecode` is populated), issue an `eth_getCode` RPC call for the contract's address against the mirror node's web3 endpoint.
3. `findRuntimeBytecode(contractId)` executes the native query, finds `runtime_bytecode IS NULL`, and returns `Optional.empty()`.
4. Because `Optional.empty() != null`, the `unless` condition is `false` and the empty Optional is stored in the Caffeine cache under the contract's ID key.
5. After `runtime_bytecode` is populated in the DB, repeat the `eth_getCode` call. The cache is hit; `Optional.empty()` is returned; `readFromDataSource()` returns `null`; the EVM layer reports no bytecode.
6. This state persists for 1 hour (`expireAfterAccess=1h`) from the last access, or indefinitely if the query is repeated before expiry.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/SidecarContractMigration.java (L44-48)
```java
        jdbcOperations.batchUpdate(
                UPDATE_RUNTIME_BYTECODE_SQL, contractBytecodes, BATCH_SIZE, (ps, contractBytecode) -> {
                    ps.setLong(1, EntityId.of(contractBytecode.getContractId()).getId());
                    ps.setBytes(2, DomainUtils.toBytes(contractBytecode.getRuntimeBytecode()));
                });
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/ContractResultServiceImpl.java (L425-425)
```java
        sidecarContractMigration.migrate(contractBytecodes);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L42-46)
```java
        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
```
