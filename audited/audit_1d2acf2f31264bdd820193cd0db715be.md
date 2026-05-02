### Title
Cache Negative-Result Poisoning via Incorrect `unless` Condition on `Optional` Return Type in `findRuntimeBytecode`

### Summary
`ContractRepository.findRuntimeBytecode()` uses `@Cacheable` with `unless = "#result == null"`, but the method returns `Optional<byte[]>`. When the `contract` table has no row for a given `contractId`, Spring Data JPA returns `Optional.empty()` — a non-null object — so the `unless` guard never fires and the empty result is cached for up to 1 hour (`expireAfterAccess=1h`). Any unprivileged caller who queries a contractId during the window when the importer has not yet written the `contract` row will lock the cache into a "no bytecode" state, causing all subsequent EVM calls against that contract to fail even after the importer recovers and inserts the correct row.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** The `unless` SpEL expression `"#result == null"` tests whether the returned Java object reference is null. When the SQL query matches no rows, Spring Data JPA wraps the absence of a result in `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` evaluates to `false`, and Spring's caching interceptor stores the empty `Optional` in the Caffeine cache under the key `contractId`. The cache is configured with `expireAfterAccess=1h` (see `CacheProperties.java` line 22), meaning every access resets the TTL.

**Exploit flow:**

1. The importer fails (crash, sidecar parse error, network partition) before it writes the `contract` table row for a newly created contract. The `entity` table row may already exist (entity and contract writes are separate calls: `entityListener.onEntity()` at line 118 and `entityListener.onContract()` at line 152 of `ContractCreateTransactionHandler.java`).
2. An unprivileged user sends any web3 call (e.g., `eth_call`, `eth_getCode`) that resolves to `ContractBytecodeReadableKVState.readFromDataSource()` (`ContractBytecodeReadableKVState.java` lines 39–47), which calls `contractRepository.findRuntimeBytecode(entityId.getId())`.
3. The SQL `select runtime_bytecode from contract where id = :contractId` returns zero rows → `Optional.empty()`.
4. Because `Optional.empty() != null`, the `unless` guard is false → `Optional.empty()` is stored in the Caffeine cache.
5. The importer recovers and inserts the correct `contract` row with valid `runtime_bytecode`.
6. All subsequent calls to `findRuntimeBytecode` for that `contractId` hit the cache and return `Optional.empty()` — the database is never re-queried.
7. `readFromDataSource` returns `null` (`.orElse(null)` at line 46), so the EVM sees no bytecode for the contract.
8. The attacker can keep issuing requests to reset the `expireAfterAccess` timer, making the poisoned entry persist indefinitely.

**Why existing checks fail:** The only guard is `unless = "#result == null"`. Spring's `@Cacheable` evaluates this after the method returns. Because `Optional.empty()` is not null, the condition never excludes the negative result from being cached. There is no secondary validation, no TTL short enough to self-heal quickly, and no cache eviction triggered by importer recovery.

### Impact Explanation
The EVM layer (`ContractBytecodeReadableKVState`) treats a `null` return from `readFromDataSource` as "contract has no code." Any `eth_call` or `eth_estimateGas` targeting the affected contract will behave as if the contract does not exist (empty bytecode), returning incorrect results or reverting. This persists for the full cache lifetime — at minimum 1 hour, indefinitely if the attacker keeps the entry alive with repeated accesses. The impact is denial-of-correct-service for all users of the web3 API against that contract, not just the attacker.

### Likelihood Explanation
The precondition (importer temporarily failing to write the `contract` row) is a realistic operational event: sidecar parse failures, transient DB errors, or importer restarts during high load can all create this window. The exploit requires no credentials, no special knowledge beyond a valid contract address (observable on-chain), and no complex tooling — a single `eth_getCode` RPC call suffices to poison the cache. The attack is repeatable and can be automated to keep the cache entry alive indefinitely.

### Recommendation
Change the `unless` condition to also exclude empty `Optional` values:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures that only a genuinely present bytecode result is cached, and a missing `contract` row will always trigger a fresh database query on the next call, allowing the system to self-heal once the importer writes the row.

### Proof of Concept
1. Identify a contract whose `entity` row exists but whose `contract` row is absent (e.g., during an importer outage window, or by directly deleting the `contract` row in a test environment).
2. Send `eth_getCode` (or any `eth_call`) to the web3 endpoint targeting that contract address.
3. Observe `Optional.empty()` is returned and cached (confirm via cache metrics or by inserting the `contract` row and immediately re-querying — the correct bytecode is not returned).
4. Insert the correct `contract` row into the database.
5. Re-query within 1 hour: the response still shows empty bytecode, confirming the cache is serving the poisoned entry.
6. Repeat step 2 every few minutes to reset `expireAfterAccess` and keep the poisoned entry alive indefinitely.