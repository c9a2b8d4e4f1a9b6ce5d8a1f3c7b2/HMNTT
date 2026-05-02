### Title
Indefinite Stale Runtime Bytecode Served via `expireAfterAccess` Caffeine Cache with No Invalidation in `findRuntimeBytecode()`

### Summary
`ContractRepository.findRuntimeBytecode()` caches results in a Caffeine cache configured with `expireAfterAccess=1h`. Because the policy resets the TTL on every read rather than expiring after write, any unprivileged user who continuously queries a contract whose `runtime_bytecode` was updated in the DB will prevent the cache entry from ever expiring, causing the mirror node to serve the old, incorrect bytecode indefinitely. No `@CacheEvict` or `@CachePut` exists anywhere in the codebase to invalidate the entry when the DB record changes.

### Finding Description

**Exact code path:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18:
```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

The cache manager `CACHE_MANAGER_CONTRACT` is configured in `CacheProperties.java` line 22:
```
expireAfterAccess=1h,maximumSize=1000,recordStats
```

`expireAfterAccess` resets the expiry timer on every cache read. A user who queries the same contract repeatedly will keep the cache entry alive indefinitely — the 1-hour window never closes as long as traffic continues.

**Root cause:** The cache policy is `expireAfterAccess` (not `expireAfterWrite`). The implicit assumption is that `runtime_bytecode` is immutable once cached. This assumption is false: `SidecarContractMigration` performs an explicit upsert (`ON CONFLICT DO UPDATE SET runtime_bytecode = excluded.runtime_bytecode`) that can change the bytecode in the DB at any time during normal importer operation.

**No invalidation path exists:** A grep across the entire codebase for `@CacheEvict` / `@CachePut` returns zero hits for the contract cache. The only evictions found are in `AddressBookServiceImpl` and `RecordFileRepository`, which are unrelated.

**`unless` condition is insufficient:** `unless = "#result == null"` only skips caching when the return value is the Java `null` reference. The method returns `Optional<byte[]>`, so `#result` is the `Optional` wrapper. `Optional.empty()` is not `null`, so "contract not found" results are also permanently cached — a separate but related staleness issue.

**Exploit flow:**
1. Contract `0.0.X` is deployed with bytecode `A`; importer writes `A` to `contract.runtime_bytecode`.
2. Attacker (or any user) calls `eth_getCode(0.0.X)` → cache miss → DB queried → bytecode `A` stored in Caffeine under key `contractId`.
3. Importer processes a sidecar record and upserts bytecode `B` into the DB for the same contract.
4. Attacker (or any user) calls `eth_getCode(0.0.X)` again → cache hit → stale bytecode `A` returned.
5. Because the policy is `expireAfterAccess`, each call in step 4 resets the 1-hour timer. As long as any client queries this contract at least once per hour, the stale entry never expires and bytecode `B` is never served.

### Impact Explanation
`findRuntimeBytecode()` is the sole data source for `ContractBytecodeReadableKVState.readFromDataSource()`, which feeds the EVM execution engine. Serving stale bytecode means:
- `eth_getCode` returns the wrong bytecode to callers.
- EVM `EXTCODECOPY` / `EXTCODESIZE` / `EXTCODEHASH` opcodes operate on the wrong code.
- Smart contract calls that depend on the deployed code of another contract (e.g., proxy pattern verification, delegate-call targets) will silently use the old logic.
- Under continuous traffic the stale state is permanent for the lifetime of the process, not just 1 hour.

Severity: **Medium–High**. Incorrect bytecode served by a mirror node undermines the correctness guarantee of the read API and can cause downstream integrations (wallets, dApps, indexers) to make decisions based on wrong contract logic.

### Likelihood Explanation
- The trigger condition (a `runtime_bytecode` update) occurs during normal importer operation whenever sidecar records are processed — no attacker action is required to cause the DB change.
- Any unprivileged user can populate the cache before the update and keep it alive after by issuing periodic `eth_getCode` calls — a standard, unauthenticated JSON-RPC request.
- The attack is fully repeatable: every contract that receives a bytecode update and has any read traffic is affected.
- No special knowledge, credentials, or network position is required.

### Recommendation
1. **Change the eviction policy** from `expireAfterAccess` to `expireAfterWrite` for the contract cache. This bounds staleness to a fixed window regardless of read traffic:
   ```
   expireAfterWrite=1h,maximumSize=1000,recordStats
   ```
2. **Add explicit cache invalidation** in the importer path that updates `runtime_bytecode`. Wherever `SidecarContractMigration` (or any other writer) upserts the `contract` table, add a `@CacheEvict` or programmatic eviction for the affected `contractId` key in `CACHE_MANAGER_CONTRACT`.
3. **Fix the `unless` condition** to also exclude empty Optionals:
   ```java
   unless = "#result == null || !#result.isPresent()"
   ```
   This prevents "not found" results from being permanently cached when a contract is later created.

### Proof of Concept

```
# 1. Populate cache with current bytecode
curl -X POST http://mirror-node:8545 \
  -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x<contract_address>","latest"],"id":1}'
# Returns: {"result":"0x<bytecode_A>"}

# 2. (Out-of-band) Importer processes sidecar and updates runtime_bytecode to bytecode_B in DB.
#    Verify: SELECT runtime_bytecode FROM contract WHERE id = <id>;  -- returns bytecode_B

# 3. Query again immediately after DB update
curl -X POST http://mirror-node:8545 \
  -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x<contract_address>","latest"],"id":2}'
# Returns: {"result":"0x<bytecode_A>"}  <-- stale, should be bytecode_B

# 4. Keep querying every 30 minutes to reset the expireAfterAccess timer.
#    The cache entry never expires; bytecode_B is never served.
while true; do
  curl -s -X POST http://mirror-node:8545 \
    -d '{"jsonrpc":"2.0","method":"eth_getCode","params":["0x<contract_address>","latest"],"id":3}'
  sleep 1800
done
# All responses continue to return bytecode_A indefinitely.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** importer/src/main/java/org/hiero/mirror/importer/migration/SidecarContractMigration.java (L26-30)
```java
    private static final String UPDATE_RUNTIME_BYTECODE_SQL = """
            insert into contract (id, runtime_bytecode)
            values (?, ?)
            on conflict (id)
            do update set runtime_bytecode = excluded.runtime_bytecode""";
```
