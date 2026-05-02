### Title
Negative Cache Poisoning via Incorrect `unless` Condition on `findRuntimeBytecode()` Allows Unprivileged DoS Against Newly Deployed Contracts

### Summary
`findRuntimeBytecode()` returns `Optional<byte[]>`, but the `@Cacheable` guard `unless = "#result == null"` only excludes a literal `null` return from being cached. Because Spring Data JPA returns `Optional.empty()` (a non-null object) when no row is found, every miss for a non-existent contract ID is cached. An unprivileged attacker can pre-poison cache entries for predictable future contract IDs, causing those contracts to appear bytecode-less to the EVM for up to one hour after deployment.

### Finding Description
**File:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

Spring's SpEL expression `#result == null` is evaluated against the actual return value of the method, which is the `Optional<byte[]>` wrapper object. When the contract does not exist in the database, the repository returns `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` evaluates to `false`, and the `unless` condition does **not** suppress caching. The empty `Optional` is stored in the Caffeine cache under the key `contractId`.

The cache is configured with `expireAfterAccess=1h, maximumSize=1000` (default in `CacheProperties.java` line 22). The downstream consumer `ContractBytecodeReadableKVState.readFromDataSource()` (lines 42–46) calls `findRuntimeBytecode()` and maps the result, returning `null` when the `Optional` is empty — making the contract appear non-existent to the EVM for the entire cache lifetime.

Hedera entity IDs are sequential integers, publicly observable via the mirror node REST API. An attacker can determine the current maximum entity ID and issue `eth_getCode` (or any `eth_call`) requests for IDs `max+1` through `max+1000` before those contracts are deployed. Each miss populates the cache. When legitimate contracts are subsequently deployed with those IDs, the cache continues to serve `Optional.empty()` for up to one hour, and every EVM call to those contracts fails.

The existing `unless` guard is the only protection against caching negative results; it is structurally insufficient because it does not account for the `Optional` wrapper.

### Impact Explanation
Any EVM call routed through the web3 module to a newly deployed contract whose ID was pre-poisoned will fail for up to one hour. The attacker can sustain the attack by periodically re-querying the poisoned IDs (resetting the `expireAfterAccess` timer), extending the DoS window indefinitely. Up to 1,000 contract IDs can be poisoned simultaneously (the cache `maximumSize`). This disrupts contract execution, token operations, and any dApp relying on those contracts during the poisoning window.

### Likelihood Explanation
No privileges are required. The attacker only needs unauthenticated HTTP access to the web3 JSON-RPC endpoint (e.g., `eth_getCode` with a long-zero EVM address derived from the predicted entity ID). Hedera entity IDs are monotonically increasing and publicly visible, making prediction trivial. The attack is fully repeatable and scriptable with a simple loop.

### Recommendation
Change the `unless` condition to also exclude `Optional.empty()`:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures only confirmed, non-empty bytecode results are cached, and cache misses (non-existent contracts) always fall through to the database.

### Proof of Concept
1. Query the mirror node REST API to obtain the current maximum entity ID (`N`).
2. For each ID in `[N+1, N+1000]`, send:
   ```
   POST /api/v1/contracts/call
   {"data":"0x","to":"0x000000000000000000000000000000000000<N+i>"}
   ```
   Each call triggers `findRuntimeBytecode(N+i)`, which returns `Optional.empty()` and caches it.
3. Deploy a legitimate contract on the Hedera network; it receives entity ID `N+1`.
4. Within one hour of step 2, attempt to call the newly deployed contract via the web3 API. The call fails because the cache returns `Optional.empty()` for `N+1`, and `ContractBytecodeReadableKVState` returns `null` bytecode to the EVM.
5. Repeat step 2 every ~55 minutes to keep the `expireAfterAccess` timer from expiring, sustaining the DoS indefinitely. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/ContractBytecodeReadableKVState.java (L42-46)
```java
        return contractRepository
                .findRuntimeBytecode(entityId.getId())
                .map(Bytes::wrap)
                .map(Bytecode::new)
                .orElse(null);
```
