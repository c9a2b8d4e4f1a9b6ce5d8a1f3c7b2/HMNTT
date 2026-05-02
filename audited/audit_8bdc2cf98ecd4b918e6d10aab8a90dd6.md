### Title
Negative Caching of `Optional.empty()` in `findRuntimeBytecode` Permanently Poisons Contract Bytecode Lookup for Up to 1 Hour

### Summary
`ContractRepository.findRuntimeBytecode()` uses `@Cacheable` with `unless = "#result == null"`, but when a contract does not yet exist in the DB the method returns `Optional.empty()` — a non-null object — which is therefore cached. Any unprivileged user who queries a contractId before its bytecode is written to the mirror node DB will cause `Optional.empty()` to be stored in the Caffeine cache with a 1-hour `expireAfterAccess` TTL, making the contract's bytecode permanently unavailable through the web3 API for up to one hour after deployment.

### Finding Description
**Exact location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** The `unless` SpEL expression is `#result == null`. Spring evaluates this after the method returns. When the contract row does not exist in the DB, Spring Data JPA returns `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` evaluates to `false`, and the empty Optional is written into the Caffeine cache.

**Cache TTL:** Defined in `CacheProperties.java` line 22:
```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```
The cache manager is configured in `EvmConfiguration.java` lines 67–73 using this specification. `expireAfterAccess=1h` means every subsequent read of the poisoned entry resets the 1-hour window, potentially extending the denial indefinitely under repeated access.

**Exploit flow:**
1. Attacker observes a pending `ContractCreate` transaction on the Hedera network (entity IDs are sequential and predictable).
2. Before the mirror node importer writes the contract row + bytecode to the DB, the attacker sends any web3 request that triggers `findRuntimeBytecode(contractId)` — e.g., `eth_getCode`, `eth_call`, or `eth_estimateGas` targeting the new contract address.
3. The DB query returns `Optional.empty()` (contract not yet present). Spring caches this result because `Optional.empty() != null`.
4. The importer subsequently writes the contract and its `runtime_bytecode` to the DB.
5. All future calls to `findRuntimeBytecode(contractId)` hit the cache and return `Optional.empty()` — the DB is never re-queried.
6. `ContractBytecodeReadableKVState.readFromDataSource()` receives `Optional.empty()`, maps to `null`, and the EVM treats the address as having no code.

**Why the existing check fails:** `unless = "#result == null"` is the only guard. It correctly excludes a Java `null` return, but `Optional.empty()` is explicitly designed to be a non-null absence sentinel. The condition must also exclude the empty-Optional case.

### Impact Explanation
Any contract deployed on Hedera becomes inaccessible through the mirror node's web3 API for up to 1 hour (or longer if the cache entry is kept alive by repeated reads). `eth_getCode` returns `0x`, and all `eth_call`/`eth_estimateGas` requests to the contract fail as if the address is an EOA. This breaks every dApp or integration that relies on the mirror node's JSON-RPC endpoint to interact with newly deployed contracts.

### Likelihood Explanation
No privileges are required. Hedera entity IDs are sequential integers, making the target contractId trivially predictable from the pending transaction visible on-chain. The attacker only needs to win a race against the importer's processing latency (typically seconds). The attack is repeatable: after the cache entry expires, the attacker can re-poison it. A single HTTP request is sufficient; no concurrent requests are needed (though concurrency makes it easier to win the race).

### Recommendation
Change the `unless` condition to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This prevents `Optional.empty()` from ever being stored in the cache, ensuring every miss falls through to the DB until the bytecode is actually present.

### Proof of Concept
1. Observe a pending `ContractCreate` transaction; note the assigned contractId (e.g., `0.0.12345`).
2. Before the mirror node importer processes the record, send:
   ```
   POST /api/v1/contracts/call
   { "to": "0x0000000000000000000000000000000000003039", "data": "0x" }
   ```
   or `eth_getCode` via JSON-RPC for the same address.
3. Confirm the mirror node returns empty bytecode (`0x`).
4. Wait for the importer to finish processing (check REST API `/api/v1/contracts/0.0.12345` shows the contract exists).
5. Repeat the `eth_getCode` call — it still returns `0x` despite the contract being fully deployed.
6. Confirm the cache is the cause by waiting 1 hour (or restarting the web3 service) and retrying — the correct bytecode is now returned. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L42-46)
```java
        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
```
