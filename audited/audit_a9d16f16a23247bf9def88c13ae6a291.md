### Title
Stale Bytecode Cache Served for Deleted Contracts Due to Missing Cache Invalidation in `findRuntimeBytecode()`

### Summary
`ContractRepository.findRuntimeBytecode()` caches contract bytecode with a 1-hour access-based TTL and no eviction on contract deletion. After a contract is deleted on-chain, the mirror node's web3 module continues serving the cached bytecode for up to one hour, causing EVM simulations (`eth_call`, `eth_estimateGas`) to treat the deleted contract as live and produce incorrect results. No privileged access is required to trigger this.

### Finding Description

**Exact code location:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

The cache is configured in `CacheProperties.java` line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

This means any bytecode fetched is cached for **1 hour from last access** with no write-based expiry.

**Root cause — two compounding failures:**

1. **No cache eviction on deletion.** `ContractDeleteTransactionHandler.doUpdateEntity()` (lines 41–57) only calls `entityListener.onEntity(entity)` with `entity.setDeleted(true)`. It never evicts the bytecode cache. A grep across the entire codebase confirms `@CacheEvict` is used only in `AddressBookServiceImpl` — never for the contract bytecode cache.

2. **`unless = "#result == null"` is a no-op for `Optional` return types.** The method returns `Optional<byte[]>`. Spring caches the `Optional` object itself. `Optional.empty()` is not `null`, so the condition never suppresses caching. All results — both found and not-found — are cached unconditionally.

**Exploit flow:**

The call chain is: external HTTP request → `ContractBytecodeReadableKVState.readFromDataSource()` (lines 39–47) → `contractRepository.findRuntimeBytecode()`. `readFromDataSource()` performs no check on the entity's `deleted` flag before calling the repository:
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
```

**The test `ContractRepositoryTest.findRuntimeBytecodeSuccessfulCall` (lines 18–31) explicitly confirms and asserts this behavior:**
```java
contractRepository.deleteAll();
// Still returns cached bytecode — test asserts this passes
assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
        .get()
        .isEqualTo(contract1.getRuntimeBytecode());
```

### Impact Explanation
During the up-to-1-hour stale window, any `eth_call` or `eth_estimateGas` directed at a deleted contract's address will find bytecode in the cache, execute the contract's EVM code, and return a successful simulation result. The mirror node thus exports incorrect records: it reports that a non-existent contract has live bytecode and executable code. Applications relying on these simulations (e.g., DeFi frontends, wallets, indexers) will receive false confirmations that a deleted contract is still operational, potentially leading to incorrect transaction construction or financial decisions.

### Likelihood Explanation
This requires no privileges. Any user who queried a contract before its deletion (or who queries it within the cache window) triggers the stale-cache path. Contract deletions are public on-chain events, so an attacker can time queries to maximize the stale window. The 1-hour `expireAfterAccess` TTL means repeated queries reset the expiry, potentially keeping stale data indefinitely as long as the contract is queried at least once per hour. The behavior is repeatable and deterministic.

### Recommendation
1. **Add `@CacheEvict` in the contract deletion path.** In `ContractDeleteTransactionHandler.doUpdateEntity()` or the downstream entity persistence layer, evict the `CACHE_NAME_CONTRACT` entry keyed by the contract's numeric ID when `deleted = true` is set.
2. **Fix the `unless` condition.** Change to `unless = "#result != null && !#result.isPresent()"` to correctly suppress caching of empty Optionals, and separately handle eviction for deletions.
3. **Add a deleted-flag check in `ContractBytecodeReadableKVState.readFromDataSource()`.** Query the entity's `deleted` status via `commonEntityAccessor` before returning bytecode, as a defense-in-depth measure.
4. **Consider switching to `expireAfterWrite`** instead of `expireAfterAccess` to bound the maximum staleness regardless of query frequency.

### Proof of Concept
1. Deploy a smart contract on the network; its `runtime_bytecode` is stored in the `contract` table.
2. Send an `eth_call` to the mirror node web3 API targeting that contract — this populates the `CACHE_NAME_CONTRACT` cache entry for the contract's ID.
3. Submit a `ContractDeleteInstance` transaction on-chain; the importer processes it and sets `entity.deleted = true` in the `entity` table. The `contract.runtime_bytecode` row remains. No cache eviction occurs.
4. Within 1 hour of step 2, send another `eth_call` to the same contract address via the mirror node.
5. `ContractBytecodeReadableKVState.readFromDataSource()` calls `findRuntimeBytecode()`, which returns the cached `Optional<byte[]>` without hitting the database.
6. The EVM simulation executes against the deleted contract's bytecode and returns a successful result — confirming the mirror node is exporting incorrect records for a contract that no longer exists. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/test/java/org/hiero/mirror/web3/repository/ContractRepositoryTest.java (L25-30)
```java
        contractRepository.deleteAll();

        assertThat(contractRepository.findRuntimeBytecode(contract1.getId()))
                .get()
                .isEqualTo(contract1.getRuntimeBytecode());
        assertThat(contractRepository.findRuntimeBytecode(contract2.getId())).isEmpty();
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
