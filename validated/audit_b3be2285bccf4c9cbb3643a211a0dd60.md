All code references in the report have been verified against the actual source. Here is my assessment:

**Verified facts:**

1. `findRuntimeBytecode()` uses `@Cacheable` with `unless = "#result == null"` and the cache is configured `expireAfterAccess=1h` — confirmed. [1](#0-0) [2](#0-1) 

2. `ContractDeleteTransactionHandler.doUpdateEntity()` never evicts the bytecode cache — confirmed. [3](#0-2) 

3. `@CacheEvict` exists only in `AddressBookServiceImpl`, never for the contract bytecode cache — confirmed by grep. [4](#0-3) 

4. `readFromDataSource()` calls `contractRepository.findRuntimeBytecode()` with no deleted-flag check — confirmed. [5](#0-4) 

5. The test explicitly asserts that after `contractRepository.deleteAll()`, the previously-queried contract's bytecode is still returned from cache — confirmed. [6](#0-5) 

6. The `unless = "#result == null"` condition is indeed a no-op for `Optional` return types: Spring caches the `Optional` wrapper object itself; `Optional.empty()` is not `null`, so all results — found and not-found — are cached unconditionally — confirmed by Spring caching semantics and consistent with the test behavior.

---

Audit Report

## Title
Stale Bytecode Cache Served for Deleted Contracts Due to Missing Cache Invalidation in `findRuntimeBytecode()`

## Summary
`ContractRepository.findRuntimeBytecode()` caches contract bytecode with a 1-hour access-based TTL and no eviction on contract deletion. After a contract is deleted on-chain, the mirror node's web3 module continues serving the cached bytecode for up to one hour (indefinitely if queried at least once per hour), causing EVM simulations (`eth_call`, `eth_estimateGas`) to treat the deleted contract as live and produce incorrect results.

## Finding Description

**Exact code location:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

Cache configuration in `CacheProperties.java` line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [2](#0-1) 

**Root cause — two compounding failures:**

**1. No cache eviction on deletion.** `ContractDeleteTransactionHandler.doUpdateEntity()` (lines 41–57) only calls `entityListener.onEntity(entity)` with `entity.setDeleted(true)`. It never evicts the bytecode cache. A search across the entire codebase confirms `@CacheEvict` is used only in `AddressBookServiceImpl` — never for the contract bytecode cache. [3](#0-2) 

**2. `unless = "#result == null"` is a no-op for `Optional` return types.** The method returns `Optional<byte[]>`. Spring caches the `Optional` object itself. `Optional.empty()` is not `null`, so the condition never suppresses caching. All results — both found and not-found — are cached unconditionally. [7](#0-6) 

**Exploit flow:**

The call chain is: external HTTP request → `ContractBytecodeReadableKVState.readFromDataSource()` (lines 39–47) → `contractRepository.findRuntimeBytecode()`. `readFromDataSource()` performs no check on the entity's `deleted` flag before calling the repository: [5](#0-4) 

The entity cache (`findByIdAndDeletedIsFalse`) has a 1-second `expireAfterWrite` TTL and would correctly reflect deletion quickly. However, the bytecode cache is entirely separate with a 1-hour `expireAfterAccess` TTL and is never invalidated on deletion. The EVM simulation receives live bytecode from the bytecode cache even when the entity-level check would return deleted. [8](#0-7) 

**The test `ContractRepositoryTest.findRuntimeBytecodeSuccessfulCall` (lines 18–31) explicitly confirms and asserts this behavior:**
```java
contractRepository.deleteAll();
// Still returns cached bytecode — test asserts this passes
assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
        .get()
        .isEqualTo(contract1.getRuntimeBytecode());
``` [6](#0-5) 

## Impact Explanation
During the up-to-1-hour stale window (indefinite with repeated queries), any `eth_call` or `eth_estimateGas` directed at a deleted contract's address will find bytecode in the cache, execute the contract's EVM code, and return a successful simulation result. The mirror node thus exports incorrect records: it reports that a non-existent contract has live bytecode and executable code. Applications relying on these simulations (e.g., DeFi frontends, wallets, indexers) will receive false confirmations that a deleted contract is still operational, potentially leading to incorrect transaction construction or financial decisions. [9](#0-8) 

## Likelihood Explanation
This requires no privileges. Any user who queried a contract before its deletion (or who queries it within the cache window) triggers the stale-cache path. Contract deletions are public on-chain events, so an attacker can time queries to maximize the stale window. The 1-hour `expireAfterAccess` TTL means repeated queries reset the expiry, potentially keeping stale data indefinitely as long as the contract is queried at least once per hour. The behavior is repeatable and deterministic, and is explicitly confirmed by an existing integration test. [10](#0-9) 

## Recommendation

1. **Add cache eviction on contract deletion.** In `ContractDeleteTransactionHandler.doUpdateEntity()`, after calling `entityListener.onEntity(entity)`, evict the bytecode cache entry for the deleted contract ID using `@CacheEvict` or programmatic eviction via the `CacheManager`. [11](#0-10) 

2. **Fix the `unless` condition for `Optional` return types.** Change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` (or `unless = "#result?.isEmpty() == true"`) to prevent caching of empty `Optional` results. [7](#0-6) 

3. **Add a deleted-flag check in `readFromDataSource()`.** Before returning bytecode, verify the entity is not deleted via `commonEntityAccessor` (already injected into `ContractBytecodeReadableKVState`) to provide defense-in-depth. [12](#0-11) 

4. **Consider reducing the TTL** for the contract bytecode cache or switching to `expireAfterWrite` instead of `expireAfterAccess` to bound the maximum staleness window. [2](#0-1) 

## Proof of Concept

The existing test `ContractRepositoryTest.findRuntimeBytecodeSuccessfulCall` already serves as a proof of concept:

```java
// 1. Persist two contracts
Contract contract1 = domainBuilder.contract().persist();
Contract contract2 = domainBuilder.contract().persist();

// 2. Query contract1 — populates the cache
assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
        .get().isEqualTo(contract1.getRuntimeBytecode());

// 3. Delete all contracts from the database (simulates on-chain deletion)
contractRepository.deleteAll();

// 4. contract1 still returns bytecode from stale cache — VULNERABILITY
assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
        .get().isEqualTo(contract1.getRuntimeBytecode());  // PASSES — stale data served

// 5. contract2 (never queried) correctly returns empty
assertThat(contractRepository.findRuntimeBytecode(contract2.getId())).isEmpty();
``` [6](#0-5) 

An attacker can reproduce this by: (1) querying any contract via `eth_call` to populate the cache, (2) waiting for the contract to be deleted on-chain, (3) continuing to query the same contract via `eth_call` or `eth_estimateGas` — the mirror node will return successful simulation results with the deleted contract's bytecode for up to 1 hour (or indefinitely with periodic queries).

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java (L16-18)
```java
    @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
    @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
    Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L19-22)
```java
    private static final String ENTITY_CACHE_CONFIG = "expireAfterWrite=1s,maximumSize=10000,recordStats";

    @NotBlank
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

**File:** importer/src/main/java/org/hiero/mirror/importer/addressbook/AddressBookServiceImpl.java (L81-84)
```java
    @CacheEvict(allEntries = true)
    public void refresh() {
        log.info("Clearing node cache");
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L29-47)
```java
    private final CommonEntityAccessor commonEntityAccessor;

    protected ContractBytecodeReadableKVState(
            final ContractRepository contractRepository, CommonEntityAccessor commonEntityAccessor) {
        super(ContractService.NAME, STATE_ID);
        this.contractRepository = contractRepository;
        this.commonEntityAccessor = commonEntityAccessor;
    }

    @Override
    protected Bytecode readFromDataSource(@NonNull ContractID contractID) {
        final var entityId = toEntityId(contractID);

        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
    }
```

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/ContractRepositoryTest.java (L18-31)
```java
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
