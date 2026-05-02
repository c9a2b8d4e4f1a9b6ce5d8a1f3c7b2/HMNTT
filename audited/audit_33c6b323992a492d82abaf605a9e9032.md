### Title
`Optional.empty()` Cached by Incorrect `unless` Condition in `findRuntimeBytecode()` Enables Targeted Contract DoS

### Summary
`ContractRepository.findRuntimeBytecode()` uses `@Cacheable(unless = "#result == null")`, but the method returns `Optional<byte[]>`. When no bytecode exists for a given `contractId`, the method returns `Optional.empty()` — a non-null singleton object — so the `unless` guard never fires and the empty result is permanently cached. Any unprivileged caller who queries a `contractId` before its bytecode is written to the DB (e.g., during the mirror-node ingestion lag) poisons the cache for up to 1 hour per access, making the contract permanently unreachable via the web3 API for as long as the attacker keeps the entry alive.

### Finding Description

**Exact location:**
`web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18:

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** Spring Cache evaluates `#result` against the actual return value of the method. Because the return type is `Optional<byte[]>`, `#result` is the `Optional` wrapper itself — never `null`. `Optional.empty()` is a non-null singleton (`Optional.EMPTY`), so `#result == null` is always `false` for an empty result, and the empty `Optional` is stored in the cache.

**Cache configuration** (`CacheProperties.java`, line 22):
```
contract = "expireAfterAccess=1h,maximumSize=1000,recordStats"
```
`expireAfterAccess=1h` means the entry is kept alive for 1 hour after each read — an attacker who polls once per hour keeps the poisoned entry alive indefinitely.

**Downstream consumer** (`ContractBytecodeReadableKVState.java`, lines 42–46):
```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);   // returns null when Optional is empty
```
When the cache returns `Optional.empty()`, `orElse(null)` returns `null`, and the EVM treats the address as having no deployed code.

**Exploit flow:**
1. A contract is submitted to Hedera. The mirror node has a finite ingestion lag before the `runtime_bytecode` row is committed to the DB.
2. During that window, the attacker sends any web3 request that triggers `findRuntimeBytecode(contractId)` (e.g., `eth_call`, `eth_estimateGas`, `eth_getCode`).
3. The DB returns no row → method returns `Optional.empty()` → `unless` guard passes → `Optional.empty()` is stored in the Caffeine cache under key `contractId`.
4. The mirror node finishes ingestion and writes the bytecode to the DB.
5. All subsequent calls to `findRuntimeBytecode(contractId)` return the cached `Optional.empty()` without touching the DB.
6. The attacker re-queries once per hour to reset the `expireAfterAccess` timer, keeping the poisoned entry alive indefinitely.

### Impact Explanation

Every EVM execution path that needs to load bytecode for the targeted contract goes through `ContractBytecodeReadableKVState.readFromDataSource()`, which calls `findRuntimeBytecode()`. With a poisoned cache entry, the EVM receives `null` bytecode and treats the address as an EOA (no code), causing all `eth_call` / `eth_estimateGas` invocations to the contract to silently return empty data or revert. This is a targeted, contract-specific denial-of-service against the mirror node's web3 API. The attacker can selectively disable any contract they choose, with no privileged access required.

### Likelihood Explanation

The precondition — querying a `contractId` before its bytecode is indexed — is trivially achievable. Hedera transaction receipts include the assigned `contractId` immediately upon submission confirmation, while mirror-node ingestion typically lags by seconds to tens of seconds. Any user who monitors the Hedera network (or simply submits a contract themselves) can race the ingestion window. The attack requires only standard, unauthenticated HTTP calls to the mirror node's public web3 endpoint. Keeping the cache entry alive requires one request per hour, which is negligible. The maximum cache size of 1000 entries means an attacker could poison up to 1000 distinct contracts simultaneously.

### Recommendation

Change the `unless` condition to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures that only non-empty `Optional` values (i.e., contracts with actual bytecode) are stored in the cache, while absent-contract lookups always fall through to the DB.

### Proof of Concept

1. Submit a `ContractCreate` transaction to Hedera and capture the assigned `contractId` from the receipt (available before mirror-node ingestion completes).
2. Immediately send an `eth_call` to the mirror node targeting that `contractId`:
   ```
   POST /api/v1/contracts/call
   { "to": "<contractId-as-evm-address>", "data": "0x", "gas": 30000 }
   ```
3. Wait for the mirror node to finish ingesting the deployment record (confirm via `/api/v1/contracts/<contractId>` returning HTTP 200 with bytecode).
4. Repeat the `eth_call` from step 2. Observe that it still returns as if the contract has no code (empty result / revert), confirming the poisoned cache entry is being served.
5. Wait 1 hour without re-querying; the entry expires. Repeat step 2 — the call now succeeds, confirming the cache was the cause.
6. To maintain the DoS indefinitely, automate a request to the endpoint once every ~55 minutes to reset the `expireAfterAccess` timer.