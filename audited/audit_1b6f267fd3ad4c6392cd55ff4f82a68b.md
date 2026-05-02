### Title
Indefinitely Stale Contract Runtime Bytecode Served via Caffeine `expireAfterAccess` Cache with No Eviction on DB Update

### Summary
`ContractRepository.findRuntimeBytecode()` caches results in a Caffeine cache configured with `expireAfterAccess=1h` and no eviction mechanism. `SidecarContractMigration.migrate()` in the importer module updates `runtime_bytecode` directly in the DB via raw JDBC, bypassing both the JPA `@Column(updatable = false)` constraint and any cache invalidation. An unprivileged external user can keep the stale cache entry alive indefinitely by repeatedly querying the affected contract, causing the mirror node to permanently serve the pre-migration bytecode for all EVM simulation calls.

### Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

The cache manager for this method is configured in `CacheProperties.java` line 22:
```
contract = "expireAfterAccess=1h,maximumSize=1000,recordStats"
``` [2](#0-1) 

`expireAfterAccess` resets the TTL on every read. A contract queried at least once per hour will have its cache entry kept alive indefinitely.

**DB update path that bypasses the cache:**

`SidecarContractMigration.java` lines 26–48 uses raw JDBC with an upsert:
```sql
insert into contract (id, runtime_bytecode) values (?, ?)
on conflict (id) do update set runtime_bytecode = excluded.runtime_bytecode
``` [3](#0-2) 

This raw JDBC call bypasses the JPA `@Column(updatable = false)` annotation on `runtimeBytecode` in `Contract.java`: [4](#0-3) 

The importer and web3 modules are separate Spring Boot processes. The importer has no mechanism to invalidate the web3 module's in-memory Caffeine cache after updating the DB. No `@CacheEvict` or `@CachePut` is present anywhere for `CACHE_MANAGER_CONTRACT`.

**Root cause:** The cache assumes `runtime_bytecode` is write-once (consistent with `@Column(updatable = false)`), but `SidecarContractMigration` is a legitimate production code path that violates this assumption via raw JDBC, with no cross-process cache invalidation.

**Failed assumption:** The `@Cacheable` annotation implicitly assumes the underlying DB value is immutable for the lifetime of the cache entry. `SidecarContractMigration` breaks this invariant.

### Impact Explanation

All `eth_call` and contract simulation requests routed through `ContractBytecodeReadableKVState.readFromDataSource()` (which calls `findRuntimeBytecode()`) will execute against the stale pre-migration bytecode: [5](#0-4) 

This means:
- EVM simulation results are computed against wrong contract logic
- DeFi applications relying on mirror node read-only calls receive incorrect return values
- The incorrect state persists for the full lifetime of the cache entry — indefinitely if the contract is queried regularly
- There is no user-facing error; the response appears valid but contains wrong data

Severity: **Medium**. The mirror node is a read-only service (no funds at direct risk), but incorrect simulation results can cause downstream application logic errors and mislead users about contract behavior.

### Likelihood Explanation

- `SidecarContractMigration.migrate()` is triggered by migration sidecar records from the Hedera network, which is a normal operational event, not an attacker-controlled action.
- An unprivileged external user does not need to trigger the migration — they only need to query the contract before and after the migration runs.
- Keeping the stale entry alive requires only periodic `eth_call` requests to the contract (once per hour), which is trivially achievable by any API consumer.
- The `ContractRepositoryTest` explicitly demonstrates and tests that the cache survives DB deletion (`deleteAll()`), confirming the stale-read behavior is observable: [6](#0-5) 
- Likelihood: **Medium** — requires a migration event to occur, but once it does, any user can perpetuate the stale state.

### Recommendation

1. **Change cache policy from `expireAfterAccess` to `expireAfterWrite`** for the contract cache. This bounds the maximum staleness window regardless of query frequency. A short TTL (e.g., `expireAfterWrite=60s`) is appropriate given that migrations can update bytecode.

2. **Add cross-process cache invalidation**: After `SidecarContractMigration.migrate()` writes to the DB, publish an invalidation event (e.g., via a DB notification, message queue, or a dedicated invalidation endpoint on the web3 service) so the web3 module can evict the affected cache entries.

3. **Alternatively**, if `runtime_bytecode` is truly intended to be immutable after initial deployment (as `@Column(updatable = false)` implies), enforce this at the DB level with a trigger or constraint, and document that `SidecarContractMigration` is the sole exception — then add a `@CacheEvict` call in the migration path if the importer and web3 share a cache infrastructure.

### Proof of Concept

1. Deploy a contract with `runtime_bytecode = 0xAABBCC` on the Hedera network. The importer writes this to the DB.
2. Send an `eth_call` to the mirror node web3 API targeting this contract. `findRuntimeBytecode(contractId)` executes the DB query and populates the Caffeine cache with `0xAABBCC`.
3. The Hedera network emits a migration sidecar record for this contract with updated `runtime_bytecode = 0xDDEEFF`. The importer processes it via `SidecarContractMigration.migrate()`, executing the raw JDBC upsert. The DB now contains `0xDDEEFF`. No cache invalidation occurs.
4. Send another `eth_call` to the mirror node for the same contract. `findRuntimeBytecode(contractId)` returns the cached `0xAABBCC` (cache hit). The EVM executes against the old bytecode.
5. Repeat step 4 at least once every 59 minutes. The `expireAfterAccess=1h` timer resets on each access. The cache entry never expires. The mirror node permanently serves `0xAABBCC` instead of `0xDDEEFF` for all simulation calls to this contract.

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

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/SidecarContractMigration.java (L26-48)
```java
    private static final String UPDATE_RUNTIME_BYTECODE_SQL = """
            insert into contract (id, runtime_bytecode)
            values (?, ?)
            on conflict (id)
            do update set runtime_bytecode = excluded.runtime_bytecode""";

    private final EntityHistoryRepository entityHistoryRepository;
    private final EntityRepository entityRepository;
    private final JdbcOperations jdbcOperations;

    public void migrate(List<ContractBytecode> contractBytecodes) {
        if (contractBytecodes == null || contractBytecodes.isEmpty()) {
            return;
        }

        var contractIds = new HashSet<Long>();
        var stopwatch = Stopwatch.createStarted();

        jdbcOperations.batchUpdate(
                UPDATE_RUNTIME_BYTECODE_SQL, contractBytecodes, BATCH_SIZE, (ps, contractBytecode) -> {
                    ps.setLong(1, EntityId.of(contractBytecode.getContractId()).getId());
                    ps.setBytes(2, DomainUtils.toBytes(contractBytecode.getRuntimeBytecode()));
                });
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/contract/Contract.java (L34-36)
```java
    @Column(updatable = false)
    @ToString.Exclude
    private byte[] runtimeBytecode;
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
