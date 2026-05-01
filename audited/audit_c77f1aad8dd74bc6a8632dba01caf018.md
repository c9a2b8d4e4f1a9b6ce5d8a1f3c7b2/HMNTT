### Title
Stale Runtime Bytecode Served from Caffeine Cache After SidecarContractMigration Update

### Summary
`ContractRepository.findRuntimeBytecode()` caches results in a Caffeine cache with a 1-hour access-based TTL. When `SidecarContractMigration.migrate()` updates `runtime_bytecode` in the database via raw JDBC, no cache invalidation is performed. Any unprivileged user who calls the web3 API targeting a recently-migrated contract will cause the EVM to execute the old bytecode for up to one hour, producing incorrect simulation results.

### Finding Description
**Exact code path:**

`ContractRepository.java` (lines 16–18) annotates `findRuntimeBytecode()` with `@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")`. The backing Caffeine cache is configured in `CacheProperties.java` (line 22) as `expireAfterAccess=1h,maximumSize=1000,recordStats` — entries live for up to one hour from last access.

`ContractBytecodeReadableKVState.readFromDataSource()` (lines 42–46) is the EVM-layer entry point; it calls `contractRepository.findRuntimeBytecode(entityId.getId())` directly, so every EVM bytecode lookup goes through this cache.

`SidecarContractMigration.migrate()` (lines 44–48) executes:
```sql
INSERT INTO contract (id, runtime_bytecode)
VALUES (?, ?)
ON CONFLICT (id) DO UPDATE SET runtime_bytecode = excluded.runtime_bytecode
```
via raw `JdbcOperations.batchUpdate()`. This bypasses Spring's cache abstraction entirely — no `@CacheEvict`, no programmatic `cache.evict()`, no cross-service invalidation signal is issued.

**Root cause / failed assumption:** The design assumes `runtime_bytecode` is write-once (set at contract creation and never changed). `SidecarContractMigration` violates this assumption by overwriting existing bytecode rows during network-level contract migrations. The `unless = "#result == null"` guard only prevents caching absent results; it does nothing for stale positive hits.

**Why existing checks fail:** The only protection is TTL expiry (`expireAfterAccess=1h`). Because the policy is access-based (not write-based), every incoming user request resets the 1-hour clock, meaning a frequently-queried migrated contract can serve stale bytecode indefinitely as long as it keeps receiving traffic.

### Impact Explanation
The EVM simulation layer (`ContractBytecodeReadableKVState`) feeds stale bytecode directly into the Besu EVM. All `eth_call`, `eth_estimateGas`, and Hedera `ContractCallQuery` requests targeting the affected contract will execute the pre-migration logic. Return values from view functions, revert conditions, and gas estimates will all reflect the old contract semantics. This constitutes unintended smart contract behavior: the mirror node's EVM diverges from the canonical on-chain state for the duration of the cache window. No direct fund loss occurs (mirror node is read-only), but downstream integrations relying on simulation results (e.g., dApps computing expected outputs before submitting real transactions to the network) can be misled.

### Likelihood Explanation
`SidecarContractMigration` is triggered automatically during normal record-file ingestion whenever a sidecar record carries `migration=true` bytecode. This is a standard Hedera network operation (e.g., EVM version upgrades that recompile system contracts). No attacker capability is required to trigger the migration — it happens at the network level. Any unprivileged user who then queries the affected contract via the public web3 REST API will hit the stale cache. The 1-hour TTL window, extended by access resets, makes the exposure window practically unbounded for popular contracts.

### Recommendation
1. **Add `@CacheEvict` to a post-migration hook.** Introduce a method in the web3 module (or a shared cache-invalidation service) annotated with `@CacheEvict(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT)` and call it for each affected `contractId` after `SidecarContractMigration.migrate()` completes.
2. **Switch to `expireAfterWrite` for the contract cache.** Replace `expireAfterAccess=1h` with a short `expireAfterWrite` TTL (e.g., matching the `entity` cache at `expireAfterWrite=1s`) so stale entries cannot be kept alive indefinitely by traffic.
3. **Use `@CachePut` instead of raw JDBC** for bytecode updates so Spring's cache abstraction is aware of the write and can maintain consistency.

### Proof of Concept
1. Deploy a contract `C` on the Hedera network; confirm its `runtime_bytecode` is stored in the DB.
2. Send a `ContractCallQuery` for `C` via the mirror node web3 API — this populates the Caffeine cache with the current bytecode.
3. Trigger a network-level sidecar migration that updates `C`'s `runtime_bytecode` in the DB (e.g., via a record file containing a `TransactionSidecarRecord` with `migration=true` and new bytecode for `C`). `SidecarContractMigration.migrate()` executes the UPSERT; the DB now holds new bytecode.
4. Immediately send another `ContractCallQuery` for `C` via the web3 API. Observe that the EVM executes the **old** bytecode (cache hit), returning results inconsistent with the updated on-chain contract logic.
5. Repeat step 4 continuously — each request resets the `expireAfterAccess` clock, keeping the stale entry alive beyond the nominal 1-hour TTL.
6. Only after 1 hour of zero traffic (or a service restart) will the cache expire and the correct bytecode be loaded.