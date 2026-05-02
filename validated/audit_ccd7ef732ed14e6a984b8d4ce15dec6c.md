All core claims are verifiable in the codebase. Here is the result:

---

Audit Report

## Title
Indefinite Stale Runtime Bytecode Served via `expireAfterAccess` Caffeine Cache with No Invalidation in `findRuntimeBytecode()`

## Summary
`ContractRepository.findRuntimeBytecode()` is cached with a Caffeine `expireAfterAccess=1h` policy and no `@CacheEvict` or `@CachePut` counterpart. Because `SidecarContractMigration` can update `runtime_bytecode` in the DB during normal importer operation, any contract that receives a bytecode update while under continuous read traffic will have its stale cache entry kept alive indefinitely, causing the mirror node to serve incorrect bytecode for `eth_getCode` and EVM execution.

## Finding Description

**Exact code path confirmed:**

`ContractRepository.findRuntimeBytecode()` is annotated with `@Cacheable` using `CACHE_MANAGER_CONTRACT`: [1](#0-0) 

The `CACHE_MANAGER_CONTRACT` bean is configured via `CacheProperties.contract`, which defaults to `expireAfterAccess=1h,maximumSize=1000,recordStats`: [2](#0-1) 

The bean wires this spec directly into a `CaffeineCacheManager`: [3](#0-2) 

**`expireAfterAccess` resets the TTL on every read.** Under continuous traffic the 1-hour window never closes, so a stale entry is never evicted.

**No invalidation path exists.** A search for `@CacheEvict` / `@CachePut` across the entire codebase returns hits only in `AddressBookServiceImpl` and `RecordFileRepository` — neither touches the contract cache. The contract cache has zero eviction hooks.

**The "immutability" assumption is false.** `SidecarContractMigration.migrate()` performs an explicit upsert that overwrites `runtime_bytecode` in the DB during normal importer operation: [4](#0-3) 

**`unless = "#result == null"` is insufficient.** The method returns `Optional<byte[]>`. In SpEL, `#result` is the `Optional` wrapper object, not its contents. `Optional.empty()` is not `null`, so "contract not found" results are also permanently cached — a separate staleness issue for contracts that are later deployed.

**Downstream consumer confirmed.** `ContractBytecodeReadableKVState.readFromDataSource()` is the sole consumer of `findRuntimeBytecode()` and feeds the EVM execution engine directly: [5](#0-4) 

## Impact Explanation
`readFromDataSource()` feeds the EVM engine used for `eth_getCode`, `EXTCODECOPY`, `EXTCODESIZE`, `EXTCODEHASH`, and all smart contract calls. Serving stale bytecode means:
- `eth_getCode` returns the wrong bytecode to callers.
- EVM opcodes that inspect external contract code operate on the wrong data.
- Proxy pattern verification, delegate-call targets, and any integration that depends on the deployed code of a contract will silently use the old logic.
- Under continuous traffic the stale state is permanent for the lifetime of the process, not bounded by the 1-hour window.

## Likelihood Explanation
- The trigger condition (`runtime_bytecode` update via `SidecarContractMigration`) occurs during normal importer operation whenever sidecar records are processed — no attacker action is required to cause the DB change.
- Any unprivileged user can populate the cache before the update and keep it alive after by issuing periodic `eth_getCode` calls — a standard, unauthenticated JSON-RPC request.
- No special credentials, network position, or knowledge is required.

## Recommendation
1. **Change `expireAfterAccess` to `expireAfterWrite`** for the contract cache in `CacheProperties.java`. This bounds staleness to a fixed wall-clock window regardless of read traffic.
2. **Fix the `unless` condition.** Change `unless = "#result == null"` to `unless = "#result == null || !#result.isPresent()"` (or `unless = "#result?.isEmpty() == true"`) so that `Optional.empty()` results are not permanently cached.
3. **Consider a shorter TTL.** Given that `SidecarContractMigration` can update bytecode at any time, a 1-hour write-based TTL is still long. A shorter `expireAfterWrite` (e.g., 5–10 minutes) reduces the staleness window.
4. **Add `@CacheEvict` in `SidecarContractMigration.migrate()`** to proactively invalidate affected contract cache entries after each upsert, if the importer and web3 module share a cache store.

## Proof of Concept
1. Contract `0.0.X` is deployed with bytecode `A`; importer writes `A` to `contract.runtime_bytecode`.
2. Client calls `eth_getCode(0.0.X)` → cache miss → DB queried → bytecode `A` stored in Caffeine under key `contractId`.
3. Importer processes a sidecar record and executes `SidecarContractMigration.migrate()`, upserting bytecode `B` into the DB for the same contract.
4. Client calls `eth_getCode(0.0.X)` again → cache hit → stale bytecode `A` returned.
5. Because the policy is `expireAfterAccess`, each call in step 4 resets the 1-hour timer. As long as any client queries this contract at least once per hour, the stale entry never expires and bytecode `B` is never served.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/SidecarContractMigration.java (L26-30)
```java
    private static final String UPDATE_RUNTIME_BYTECODE_SQL = """
            insert into contract (id, runtime_bytecode)
            values (?, ?)
            on conflict (id)
            do update set runtime_bytecode = excluded.runtime_bytecode""";
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
