### Title
Negative Cache Poisoning via `Optional.empty()` in `findRuntimeBytecode` Allows DoS Against Newly Deployed Contracts

### Summary
The `@Cacheable` annotation on `findRuntimeBytecode` uses `unless = "#result == null"` to prevent caching absent results. However, when a contract does not exist, Spring Data JPA returns `Optional.empty()` — a non-null object — so the `unless` guard evaluates to `false` and the empty `Optional` is stored in the cache. An unprivileged attacker can pre-query a predictable contract address before deployment, poison the cache with an empty result, and cause all subsequent bytecode lookups for that contract to return empty for up to one hour.

### Finding Description

**Exact code location:**

`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, lines 16–18: [1](#0-0) 

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** The SpEL expression `#result == null` evaluates against the `Optional` wrapper object, not the value inside it. When no contract row exists, the repository returns `Optional.empty()`. `Optional.empty()` is a singleton non-null object, so `#result == null` is `false`, and Spring's caching infrastructure proceeds to store the empty `Optional` in the cache. The intended guard — "do not cache a miss" — is never triggered.

**Cache TTL:** The contract cache is configured as `expireAfterAccess=1h,maximumSize=1000,recordStats`: [2](#0-1) 

`expireAfterAccess` means the entry lives for one hour after the *last access*, not after insertion. An attacker who periodically re-queries the poisoned ID can keep the stale entry alive indefinitely.

**Call path that consumes the cached result:** [3](#0-2) 

`ContractBytecodeReadableKVState.readFromDataSource` calls `contractRepository.findRuntimeBytecode(entityId.getId())`. When the cache returns `Optional.empty()`, the method returns `null` (no bytecode), making the EVM treat the address as a non-contract account.

**Why the existing check is insufficient:** The only guard is `unless = "#result == null"`. There is no check for `#result.isPresent()`, no negative-cache TTL shorter than the positive-cache TTL, and no cache invalidation path triggered by contract deployment.

### Impact Explanation
Any contract whose numeric entity ID can be predicted before deployment (e.g., via CREATE2 with known salt/deployer, or by observing the monotonically increasing entity ID sequence) can be rendered non-functional for up to one hour after deployment. All `eth_call`, `eth_estimateGas`, and direct bytecode queries routed through `ContractBytecodeReadableKVState` will receive empty bytecode, causing every call to the contract to revert or return as if the address is an EOA. This is a targeted, per-contract denial-of-service with no authentication requirement.

### Likelihood Explanation
The attack requires no credentials or special privileges — only the ability to send a JSON-RPC request (e.g., `eth_call` to a not-yet-deployed address). Contract addresses are predictable: CREATE2 addresses are fully deterministic from public parameters, and standard CREATE addresses are derivable from the deployer address and nonce. The attacker needs only one successful pre-deployment query to poison the cache. The attack is repeatable and can be automated to continuously refresh the cache entry via periodic re-queries, extending the DoS window beyond one hour.

### Recommendation
Change the `unless` condition to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This mirrors the correct pattern already used elsewhere in the codebase (e.g., `unless = "@spelHelper.isNullOrEmpty(#result)"` in `AddressBookEntryRepository`). Alternatively, introduce a separate short-TTL negative cache (e.g., 2–5 seconds, consistent with `contractState` cache) for absent lookups, so misses are not cached for the full one-hour window.

### Proof of Concept

1. Identify or predict the numeric entity ID of a contract that will be deployed (e.g., observe the current max entity ID `N`; the next CREATE will be `N+1`).
2. Before deployment, send an `eth_call` (or any request that triggers `findRuntimeBytecode(N+1)`) to the mirror node web3 API. The DB returns no row → `Optional.empty()` → cached under key `N+1` for up to 1 hour.
3. Deploy the contract on the Hedera network. The importer writes the runtime bytecode to the `contract` table with `id = N+1`.
4. Immediately send `eth_call` targeting the newly deployed contract. `findRuntimeBytecode(N+1)` hits the cache, returns `Optional.empty()`, `readFromDataSource` returns `null`, and the EVM sees no bytecode — the call reverts as if the contract does not exist.
5. Repeat step 4 every ~55 minutes to keep the stale cache entry alive and extend the DoS window indefinitely.

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
