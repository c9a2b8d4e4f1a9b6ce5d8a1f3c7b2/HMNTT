### Title
Cache Poisoning via Empty Optional Not Excluded by `unless` Condition in `findRuntimeBytecode()`

### Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"`, but when no contract row exists the method returns `Optional.empty()` — a non-null object — so the guard never fires and the empty result is stored in the cache. Any unprivileged caller who triggers a lookup for a contract ID that does not yet exist will poison the cache entry for that ID for up to one hour, causing all subsequent lookups to return empty bytecode even after the contract is legitimately deployed.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** Spring's `unless` SpEL expression is evaluated against the actual return value. When the SQL query matches no row, Spring Data JPA wraps the result as `Optional.empty()`. `Optional.empty() == null` is `false`, so the `unless` guard does not suppress caching. The empty `Optional` is written into the Caffeine cache keyed on `contractId`.

**Cache configuration** (`CacheProperties.java`, line 22):
```
expireAfterAccess=1h, maximumSize=1000
```
The poisoned entry survives for up to one hour after each access.

**Call path:** An external `eth_call` / `eth_estimateGas` request → `ContractBytecodeReadableKVState.readFromDataSource()` (line 42–46) → `contractRepository.findRuntimeBytecode(entityId.getId())`. The `entityId` is derived from the caller-supplied `ContractID` via `entityIdFromContractId()` / `EntityId.of(shard, realm, num)` (line 159 of `EntityIdUtils.java`). No privilege is required to submit such a request.

**Why existing checks fail:** The only guard is `unless = "#result == null"`. Because the return type is `Optional<byte[]>`, a "not found" result is never `null`; it is always `Optional.empty()`. The condition therefore never prevents caching of negative results.

### Impact Explanation
Once a cache entry for a given `contractId` is poisoned with `Optional.empty()`, every call to `findRuntimeBytecode` for that ID within the next hour returns the cached empty value without hitting the database. `ContractBytecodeReadableKVState.readFromDataSource()` maps an empty Optional to `null` (line 46), so the EVM treats the contract as having no bytecode. This means:
- Calls to a newly deployed contract return execution failures or "no code at address" errors for up to one hour.
- The mirror node exports incorrect (missing) bytecode records for that contract during the cache lifetime.
- The window is refreshed on every access (`expireAfterAccess`), so an attacker who keeps querying the ID can extend the denial indefinitely.

### Likelihood Explanation
The attack requires no credentials. Any user who can submit a JSON-RPC `eth_call` or `eth_estimateGas` request can trigger it. The attacker only needs to know (or guess) the numeric entity ID of a contract that will be deployed soon — predictable because Hedera entity numbers are sequential. The attack is repeatable and cheap: a single HTTP request per target ID is sufficient to poison the cache, and repeated requests reset the one-hour TTL.

### Recommendation
Change the `unless` condition to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures only successful (non-empty) bytecode lookups are cached, while "not found" results always fall through to the database on the next request.

### Proof of Concept
**Precondition:** The next contract to be deployed on the network will receive entity ID `0.0.N` (predictable from the current highest entity number).

1. Before deployment, send an `eth_call` to the mirror node's web3 endpoint targeting the long-zero EVM address corresponding to `0.0.N`:
   ```
   POST /api/v1/contracts/call
   { "to": "0x000000000000000000000000000000000000000N", "data": "0x" }
   ```
2. The SQL query `select runtime_bytecode from contract where id = N` returns no rows. `findRuntimeBytecode(N)` returns `Optional.empty()`. Because `Optional.empty() != null`, the `unless` guard does not fire and `Optional.empty()` is stored in the Caffeine cache under key `N`.
3. The contract `0.0.N` is now deployed on-chain and the importer writes its bytecode to the `contract` table.
4. Send any `eth_call` to `0.0.N`. `findRuntimeBytecode(N)` returns the cached `Optional.empty()` without querying the database. `readFromDataSource()` returns `null`, and the EVM reports no bytecode at the address — the call fails as if the contract does not exist.
5. Repeat step 1 every ~59 minutes to keep the cache entry alive indefinitely.