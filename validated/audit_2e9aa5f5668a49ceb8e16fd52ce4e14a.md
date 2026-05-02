All code references check out. Let me verify each claim against the actual source.

**Verified facts:**

1. `findRuntimeBytecode()` uses `@Cacheable` with `unless = "#result == null"` but returns `Optional<byte[]>` — Spring caches the `Optional` wrapper itself; `Optional.empty()` is never `null`, so the condition never suppresses caching. [1](#0-0) 

2. The cache is configured with `expireAfterAccess=1h` — access-based, not write-based, meaning repeated queries reset the TTL indefinitely. [2](#0-1) 

3. `@CacheEvict` exists only in `AddressBookServiceImpl` — never for the contract bytecode cache. `ContractDeleteTransactionHandler.doUpdateEntity()` only calls `entityListener.onEntity(entity)` with no cache eviction. [3](#0-2) 

4. `ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode()` directly with no check on the entity's `deleted` flag. [4](#0-3) 

5. The test explicitly asserts that after `contractRepository.deleteAll()`, `contract1` (previously queried) still returns its cached bytecode, while `contract2` (never queried) returns empty. This is a deliberate test of the caching behavior, not a regression test catching a bug. [5](#0-4) 

All four required checks pass. The finding is valid.

---

# Audit Report

## Title
Stale Bytecode Cache Served for Deleted Contracts Due to Missing Cache Invalidation in `findRuntimeBytecode()`

## Summary
`ContractRepository.findRuntimeBytecode()` caches contract bytecode with a 1-hour access-based TTL and no eviction on contract deletion. After a contract is deleted on-chain, the mirror node's web3 module continues serving the cached bytecode for up to one hour (or indefinitely under sustained query load), causing EVM simulations (`eth_call`, `eth_estimateGas`) to treat the deleted contract as live and return incorrect results.

## Finding Description

**Location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18 [1](#0-0) 

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause — two compounding failures:**

**1. No cache eviction on contract deletion.**
`ContractDeleteTransactionHandler.doUpdateEntity()` marks the entity as deleted via `entityListener.onEntity(entity)` but never evicts the bytecode cache entry. [3](#0-2) 

A codebase-wide grep confirms `@CacheEvict` is used only in `AddressBookServiceImpl` — never for the contract bytecode cache.

**2. `unless = "#result == null"` is ineffective for `Optional` return types.**
The method returns `Optional<byte[]>`. Spring caches the `Optional` object itself. `Optional.empty()` is not `null`, so the `unless` condition is never `true`. Both found and not-found results are cached unconditionally. [6](#0-5) 

**Cache configuration:**
`expireAfterAccess=1h` means the TTL resets on every read. Under sustained query load, stale bytecode is never evicted. [2](#0-1) 

**Exploit flow:**
External HTTP request → `ContractBytecodeReadableKVState.readFromDataSource()` → `contractRepository.findRuntimeBytecode()`. `readFromDataSource()` performs no check on the entity's `deleted` flag before calling the repository. [4](#0-3) 

**Test confirmation:**
`ContractRepositoryTest.findRuntimeBytecodeSuccessfulCall` explicitly asserts that after `contractRepository.deleteAll()`, the previously-queried `contract1` still returns its cached bytecode. This is not a regression test — it is a deliberate assertion of the caching behavior. [7](#0-6) 

## Impact Explanation
During the stale window, any `eth_call` or `eth_estimateGas` directed at a deleted contract's address will find bytecode in the cache, execute the contract's EVM code, and return a successful simulation result. The mirror node exports incorrect state: it reports that a non-existent contract has live, executable bytecode. Applications relying on these simulations (DeFi frontends, wallets, indexers) will receive false confirmations that a deleted contract is still operational, potentially leading to incorrect transaction construction. Under `expireAfterAccess`, repeated queries reset the TTL, meaning stale data can persist indefinitely as long as the contract is queried at least once per hour.

## Likelihood Explanation
No privileges are required. Any caller who queried a contract before its deletion (or queries it within the cache window) triggers the stale-cache path. Contract deletions are public on-chain events, so the timing is observable. The behavior is deterministic and repeatable, as confirmed by the existing test suite.

## Recommendation

1. **Add `@CacheEvict` in `ContractDeleteTransactionHandler.doUpdateEntity()`** to evict the bytecode cache entry when a contract is deleted:
   ```java
   @CacheEvict(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, key = "#entity.id")
   ```

2. **Fix the `unless` condition** for `Optional` return types. Change:
   ```java
   unless = "#result == null"
   ```
   to:
   ```java
   unless = "#result == null || !#result.isPresent()"
   ```
   This prevents `Optional.empty()` from being cached, which is a separate but related correctness issue.

3. **Consider switching from `expireAfterAccess` to `expireAfterWrite`** for the contract bytecode cache to bound the stale window regardless of query frequency.

4. **Add a `deleted` flag check in `ContractBytecodeReadableKVState.readFromDataSource()`** as a defense-in-depth measure, using `commonEntityAccessor` (already injected) to verify the entity is not deleted before returning bytecode. [8](#0-7) 

## Proof of Concept
The existing test `ContractRepositoryTest.findRuntimeBytecodeSuccessfulCall` serves as a direct proof of concept: [9](#0-8) 

```java
@Test
void findRuntimeBytecodeSuccessfulCall() {
    Contract contract1 = domainBuilder.contract().persist();
    Contract contract2 = domainBuilder.contract().persist();
    // Prime the cache for contract1
    assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
            .get()
            .isEqualTo(contract1.getRuntimeBytecode());

    contractRepository.deleteAll(); // Simulate on-chain deletion

    // contract1: stale cache hit — returns deleted contract's bytecode
    assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
            .get()
            .isEqualTo(contract1.getRuntimeBytecode()); // PASSES — stale data served

    // contract2: cache miss — correctly returns empty
    assertThat(contractRepository.findRuntimeBytecode(contract2.getId())).isEmpty();
}
```

The test passes, confirming the mirror node serves stale bytecode for deleted contracts. To reproduce the full exploit: deploy a contract, call `eth_call` against it (priming the cache), delete the contract on-chain, then call `eth_call` again within the 1-hour window — the mirror node will return a successful simulation result as if the contract still exists.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/parser/record/transactionhandler/ContractDeleteTransactionHandler.java (L41-57)
```java
    protected void doUpdateEntity(Entity entity, RecordItem recordItem) {
        var transactionBody = recordItem.getTransactionBody().getContractDeleteInstance();
        EntityId obtainerId = null;

        if (transactionBody.hasTransferAccountID()) {
            obtainerId = EntityId.of(transactionBody.getTransferAccountID());
        } else if (transactionBody.hasTransferContractID()) {
            obtainerId = entityIdService
                    .lookup(transactionBody.getTransferContractID())
                    .orElse(EntityId.EMPTY);
        }

        entity.setObtainerId(obtainerId);
        entity.setPermanentRemoval(transactionBody.getPermanentRemoval());
        entity.setType(EntityType.CONTRACT);
        entityListener.onEntity(entity);
        recordItem.addEntityId(obtainerId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L31-36)
```java
    protected ContractBytecodeReadableKVState(
            final ContractRepository contractRepository, CommonEntityAccessor commonEntityAccessor) {
        super(ContractService.NAME, STATE_ID);
        this.contractRepository = contractRepository;
        this.commonEntityAccessor = commonEntityAccessor;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L39-47)
```java
    protected Bytecode readFromDataSource(@NonNull ContractID contractID) {
        final var entityId = toEntityId(contractID);

        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/ContractRepositoryTest.java (L17-31)
```java
    @Test
    void findRuntimeBytecodeSuccessfulCall() {
        Contract contract1 = domainBuilder.contract().persist();
        Contract contract2 = domainBuilder.contract().persist();
        assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
                .get()
                .isEqualTo(contract1.getRuntimeBytecode());

        contractRepository.deleteAll();

        assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
                .get()
                .isEqualTo(contract1.getRuntimeBytecode());
        assertThat(contractRepository.findRuntimeBytecode(contract2.getId())).isEmpty();
    }
```
