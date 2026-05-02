All code references check out. Let me verify the exact lines cited before rendering a verdict.

**Verified facts:**

1. `ContractRepository.java` line 16: `@Cacheable(..., unless = "#result == null")` on a method returning `Optional<byte[]>` — confirmed. [1](#0-0) 

2. `CacheProperties.java` line 22: `private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats"` — confirmed. [2](#0-1) 

3. `ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode(...).map(...).orElse(null)` — confirmed. [3](#0-2) 

4. The Caffeine cache manager for contracts is wired directly from `cacheProperties.getContract()` — confirmed. [4](#0-3) 

The root cause is technically sound: `Optional.empty()` is a non-null singleton, so `#result == null` evaluates to `false` and Spring caches it. All file/line references are accurate. The exploit flow is logically consistent with the code.

---

# Audit Report

## Title
Stale-Empty Bytecode Poisoning via `Optional.empty()` Cache Bypass in `ContractRepository.findRuntimeBytecode`

## Summary
The `@Cacheable` guard `unless = "#result == null"` on `ContractRepository.findRuntimeBytecode` does not prevent caching of `Optional.empty()`. When the database returns no rows (e.g., due to replication lag), the method returns `Optional.empty()` — a non-null object — which Spring caches in the Caffeine contract cache (`expireAfterAccess=1h, maximumSize=1000`). Any request that hits this path during the lag window poisons the cache entry for that contract ID for up to one hour after the database recovers.

## Finding Description

**Root cause:**

`ContractRepository.findRuntimeBytecode` is annotated with:

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

Spring's `unless` SpEL expression evaluates `#result` as the raw return value — an `Optional<byte[]>`. When the database returns no rows, JPA returns `Optional.empty()`. `Optional.empty()` is a non-null singleton, so `#result == null` → `false`, and Spring **caches the empty Optional**.

The cache is configured with a 1-hour access-based TTL and a maximum of 1000 entries:

```java
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
``` [2](#0-1) 

**Exploit flow:**

1. The database replica experiences replication lag; the `contract` row for a deployed contract is temporarily absent from the replica.
2. A user sends `eth_call` or `eth_estimateGas` targeting that contract.
3. `ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode(entityId.getId())`. [5](#0-4) 
4. The DB returns no rows → JPA returns `Optional.empty()` → Spring caches it (guard fails).
5. `readFromDataSource()` returns `null` via `.orElse(null)`, causing the EVM to treat the contract as non-existent. [6](#0-5) 
6. All subsequent requests for the same contract ID hit the poisoned cache entry and receive `null` bytecode for up to 1 hour, even after the database fully recovers.

**Why the existing check fails:**

The guard `unless = "#result == null"` was intended to prevent caching of absent contracts, but it only guards against a literal `null` return. `Optional.empty()` is not `null`. The correct guard would be:
```java
unless = "#result == null || !#result.isPresent()"
```

## Impact Explanation
Any contract whose bytecode lookup is served from a poisoned cache entry will be treated as non-existent by the EVM for up to 1 hour. All `eth_call`, `eth_estimateGas`, and contract execution requests targeting that contract will fail with a "contract not found" or REVERT result. With `maximumSize=1000`, up to 1000 distinct contracts can be simultaneously poisoned. This constitutes a targeted denial-of-service against specific contracts on the EVM execution layer, persisting well beyond the partition or lag recovery window.

## Likelihood Explanation
The mirror node is a read-only replica. Replication lag is a common operational condition, not a rare failure. Any unprivileged user who issues an `eth_call` to a contract during a lag window — even accidentally — poisons the cache. No special privileges, authentication, or knowledge of internals is required. The attacker only needs to know a contract address (public on-chain information) and send a standard JSON-RPC call during a lag window. The 1-hour `expireAfterAccess` TTL makes recovery slow and the window of impact large.

## Recommendation
Change the `unless` condition on `findRuntimeBytecode` to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
``` [1](#0-0) 

This ensures that only non-empty Optional results (i.e., contracts with actual bytecode) are stored in the long-lived contract cache.

## Proof of Concept
1. Deploy a contract on the network; confirm it is visible on the mirror node replica.
2. Introduce artificial replication lag (e.g., pause the replication slot or use a network partition tool) so the `contract` row is temporarily absent from the replica.
3. Send `eth_call` targeting the contract's address to the mirror node's JSON-RPC endpoint.
4. Restore replication; confirm the contract row is now present in the replica DB.
5. Send another `eth_call` to the same contract — observe that it still fails with "contract not found" despite the DB being healthy.
6. Wait for the cache TTL (up to 1 hour) to expire; confirm the call succeeds afterward.

The poisoned cache entry can be confirmed by inspecting Caffeine cache stats (`recordStats` is enabled) and observing a cache hit returning `Optional.empty()` for the affected contract ID after DB recovery.

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
