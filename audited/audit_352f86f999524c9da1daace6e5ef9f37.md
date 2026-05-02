### Title
Stale Contract Bytecode Cache Causes `eth_call` Simulations to Execute Against Pre-Upgrade Bytecode

### Summary
`ContractRepository.findRuntimeBytecode()` is annotated with `@Cacheable` using a cache configured as `expireAfterAccess=1h`. Because `expireAfterAccess` resets on every read, a frequently-queried contract's bytecode entry never expires after an upgrade. No `@CacheEvict` or invalidation mechanism exists anywhere in the codebase for this cache. Any unprivileged caller submitting an `eth_call` to a recently upgraded contract will receive simulation results computed against the old bytecode for up to — and potentially well beyond — one hour.

### Finding Description

**Code path:**

`TransactionExecutionService.execute()` (line 78) calls `transactionExecutorFactory.get()`, which returns a reused `TransactionExecutor` backed by `MirrorNodeState`. During EVM execution, contract bytecode is resolved through `ContractBytecodeReadableKVState.readFromDataSource()`:

```
ContractBytecodeReadableKVState.java:42-46
  contractRepository
      .findRuntimeBytecode(entityId.getId())
      .map(Bytes::wrap)
      .map(Bytecode::new)
      .orElse(null);
```

`ContractRepository.findRuntimeBytecode()` is declared as:

```
ContractRepository.java:16-18
  @Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
  @Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
  Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

The backing cache manager is configured in `CacheProperties.java:22`:

```
private String contract = "expireAfterAccess=1h,maximumSize=1000,recordStats";
```

**Root cause:** `expireAfterAccess=1h` resets the TTL on every cache hit. For any contract receiving steady `eth_call` traffic, the cache entry is never evicted after an upgrade. A full grep of the codebase for `@CacheEvict` returns zero hits for contract bytecode — there is no invalidation path triggered by contract upgrade processing.

**Exploit flow:**
1. Contract `C` is upgraded on the Hedera network; the importer writes new bytecode to the `contract` table.
2. The mirror node's `contract` Caffeine cache still holds the old bytecode (entry was last accessed recently, so TTL has not elapsed).
3. Attacker (no privileges required) submits `eth_call` targeting contract `C`.
4. `TransactionExecutionService.execute()` → `ContractBytecodeReadableKVState.readFromDataSource()` → `ContractRepository.findRuntimeBytecode()` → cache hit → old bytecode returned.
5. The EVM simulation runs against the old bytecode and returns results reflecting pre-upgrade logic.
6. As long as any caller queries the contract at least once per hour, the stale entry is never evicted.

**Why existing checks are insufficient:** The `unless = "#result == null"` guard on `@Cacheable` only prevents caching null results; it does not handle bytecode replacement. The `TransactionExecutorFactory` reuses executors across requests but delegates state reads to `MirrorNodeState`, which itself delegates to the cached repository — so executor reuse is not the direct cause, but it means there is no per-request state refresh either.

### Impact Explanation
Any caller using `eth_call` to simulate contract interactions before submitting real transactions (standard DeFi/wallet behavior) will receive incorrect return values, incorrect revert/success signals, and incorrect gas estimates for up to the full cache lifetime — indefinitely for popular contracts. This can cause callers to submit real transactions with incorrect parameters, approve incorrect token amounts, or incorrectly conclude a function will succeed when it will revert (or vice versa) under the upgraded logic.

### Likelihood Explanation
No attacker capability is required beyond the ability to send an HTTP request to the mirror node's JSON-RPC endpoint. The condition (a contract upgrade followed by an `eth_call` within the cache window) is routine in production environments. The `expireAfterAccess` policy makes the window unbounded for any contract with ongoing traffic. This is repeatable and deterministic.

### Recommendation
Replace `expireAfterAccess=1h` with a short `expireAfterWrite` TTL (e.g., `expireAfterWrite=2s`, consistent with `contractState`) for the contract bytecode cache, or add a `@CacheEvict(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT)` call in the contract upgrade processing path (wherever the importer writes new `runtime_bytecode` to the `contract` table). The `expireAfterAccess` semantic is specifically wrong here because it prevents eviction for popular contracts regardless of how stale the data is.

### Proof of Concept
1. Deploy contract `C` with function `foo()` returning `uint256 1`.
2. Query `eth_call` → `foo()` on the mirror node; confirm cache is populated (returns `1`).
3. Upgrade contract `C` on-chain so `foo()` now returns `uint256 2`; wait for importer to write new bytecode to DB.
4. Immediately query `eth_call` → `foo()` on the mirror node again.
5. Observe the mirror node returns `1` (old bytecode) instead of `2` (new bytecode).
6. Continue querying once every 50 minutes; observe the mirror node continues returning `1` indefinitely because each query resets the `expireAfterAccess` timer, preventing eviction.