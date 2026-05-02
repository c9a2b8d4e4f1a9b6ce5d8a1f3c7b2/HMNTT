### Title
Stale Bytecode Cache Poisoning via SidecarContractMigration Bypassing Spring Cache Eviction

### Summary
`SidecarContractMigration.migrate()` writes `runtime_bytecode` directly to the database via raw JDBC, completely bypassing the Spring Caffeine cache used by `ContractRepository.findRuntimeBytecode()`. Because no cache eviction is performed after the upsert, any external user who queries a contract immediately after a migration that wrote incorrect bytecode will cause that incorrect bytecode to be cached for up to one hour (or indefinitely under repeated access), with no mechanism to correct it short of a service restart or cache expiry.

### Finding Description

**Code path 1 — cache population with no eviction guard:**

`SidecarContractMigration.migrate()` executes a raw JDBC upsert:

```java
// SidecarContractMigration.java lines 26-30 / 44-48
private static final String UPDATE_RUNTIME_BYTECODE_SQL = """
        insert into contract (id, runtime_bytecode)
        values (?, ?)
        on conflict (id)
        do update set runtime_bytecode = excluded.runtime_bytecode""";

jdbcOperations.batchUpdate(
        UPDATE_RUNTIME_BYTECODE_SQL, contractBytecodes, BATCH_SIZE, (ps, contractBytecode) -> {
            ps.setLong(1, EntityId.of(contractBytecode.getContractId()).getId());
            ps.setBytes(2, DomainUtils.toBytes(contractBytecode.getRuntimeBytecode()));
        });
``` [1](#0-0) 

This raw JDBC call is invisible to Spring's cache abstraction. There is no `@CacheEvict` annotation, no programmatic `cache.evict()`, and no cache invalidation of any kind in `SidecarContractMigration`. A search across the entire codebase confirms the only `@CacheEvict` usages are in `AddressBookServiceImpl` — entirely unrelated to contract bytecode.

**Code path 2 — the cached query:**

```java
// ContractRepository.java lines 16-18
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [2](#0-1) 

The `unless = "#result == null"` guard only prevents caching a Java `null` return value. It does **not** prevent caching `Optional.empty()` (a non-null object), and it does not prevent caching incorrect bytecode bytes. Any non-null result — including malformed bytecode — is unconditionally stored in the cache.

**Cache TTL:**

```java
// CacheProperties.java line 22
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [3](#0-2) 

`expireAfterAccess=1h` means the TTL resets on every read. Under continuous query load the incorrect bytecode never expires.

**Downstream consumer:**

`ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode()` and wraps the result directly into a `Bytecode` object used for EVM execution:

```java
// ContractBytecodeReadableKVState.java lines 42-46
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);
``` [4](#0-3) 

No validation of the bytecode content is performed before caching or before use in EVM execution.

**Exploit flow:**
1. A malformed sidecar record (e.g., truncated, zeroed, or adversarially crafted `runtime_bytecode`) is processed by the importer.
2. `SidecarContractMigration.migrate()` upserts the incorrect bytecode for `contractId X` into the `contract` table via raw JDBC.
3. An unprivileged external user sends any web3 call that resolves contract bytecode for `X` (e.g., `eth_getCode`, `eth_call`).
4. `findRuntimeBytecode(X)` misses the cache, hits the DB, reads the incorrect bytecode, and stores it in the Caffeine cache.
5. A subsequent correct sidecar record arrives and `SidecarContractMigration.migrate()` writes the correct bytecode to the DB — but the cache is still not evicted.
6. All subsequent calls for `X` are served the incorrect cached bytecode. With any ongoing query traffic, `expireAfterAccess` resets continuously and the incorrect bytecode is served indefinitely.

### Impact Explanation
The web3 module serves incorrect `runtime_bytecode` for EVM execution. Concretely:
- `eth_getCode` returns wrong bytecode to callers.
- `eth_call` and `eth_estimateGas` execute against the wrong bytecode, producing incorrect results or reverts.
- Smart contract interactions that depend on bytecode introspection (e.g., EIP-1167 proxy detection, `EXTCODEHASH`) return wrong values.
- The incorrect state persists for the full cache lifetime — up to indefinitely under load — with no operator-visible signal and no self-healing path short of a service restart.

Severity: **Medium**. The incorrect data originates from a malformed sidecar record (not directly from the external user), but the cache architecture guarantees the incorrect data is served long after the DB is corrected, amplifying the impact of any upstream data quality issue.

### Likelihood Explanation
The precondition is a malformed sidecar record reaching the importer. This can occur via:
- A bug in a consensus node producing a malformed `TransactionSidecarRecord`.
- A compromised or Byzantine consensus node injecting bad bytecode.
- A replay or fuzzing attack against the importer's record stream ingestion.

Once the malformed record is processed, the external user's role requires zero privilege: any `eth_getCode` or `eth_call` for the affected contract ID is sufficient to lock in the incorrect bytecode. The trigger is a routine, unauthenticated RPC call. The condition is repeatable across any number of contracts processed by `SidecarContractMigration`.

### Recommendation
1. **Add cache eviction in `SidecarContractMigration.migrate()`**: After the `jdbcOperations.batchUpdate` call, evict each updated `contractId` from the `CACHE_MANAGER_CONTRACT` / `CACHE_NAME_CONTRACT` cache programmatically via `CacheManager.getCache(CACHE_NAME_CONTRACT).evict(contractId)`.
2. **Alternatively, change the cache policy** for the contract cache from `expireAfterAccess` to `expireAfterWrite` with a shorter TTL (e.g., matching the `contractState` cache at 2s) so stale entries self-heal quickly.
3. **Add a `@CacheEvict` or `@CachePut` overload** on any repository method that updates `runtime_bytecode` so that cache coherence is enforced at the repository layer rather than relying on callers to remember to evict.
4. **Validate bytecode content** before caching in `findRuntimeBytecode` or in `ContractBytecodeReadableKVState` to reject obviously malformed entries (e.g., empty or zero-length bytecode for a known contract).

### Proof of Concept
```
Precondition: importer processes a sidecar record with contractId=X and
              runtime_bytecode = 0x0000 (malformed/zeroed).

Step 1: SidecarContractMigration.migrate() executes:
        INSERT INTO contract (id, runtime_bytecode) VALUES (X, 0x0000)
        ON CONFLICT (id) DO UPDATE SET runtime_bytecode = excluded.runtime_bytecode;
        → DB now has incorrect bytecode for X.
        → Spring Caffeine cache for CACHE_NAME_CONTRACT is NOT evicted.

Step 2: External user (no auth required) sends:
        POST /api/v1/contracts/call  { "to": "<address of X>", "data": "0x..." }
        or
        eth_getCode for address of X

Step 3: ContractBytecodeReadableKVState.readFromDataSource() calls
        contractRepository.findRuntimeBytecode(X).
        Cache miss → DB query returns 0x0000 → cached in Caffeine with key X.

Step 4: Importer processes a corrected sidecar record:
        SidecarContractMigration.migrate() writes correct bytecode to DB.
        → DB is now correct.
        → Cache still holds 0x0000 for X (no eviction performed).

Step 5: All subsequent calls for X return 0x0000 from cache.
        Repeated access resets expireAfterAccess=1h timer.
        Incorrect bytecode is served indefinitely until service restart.

Verification: Query eth_getCode for X repeatedly; observe 0x0000 returned
              even after DB contains correct bytecode.
```

### Citations

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
