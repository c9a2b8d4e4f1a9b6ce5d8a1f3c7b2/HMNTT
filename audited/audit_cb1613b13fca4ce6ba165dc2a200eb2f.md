### Title
Cache Poisoning via Broken `unless` Condition on `Optional<byte[]>` Return Type

### Summary
The `@Cacheable` annotation on `findRuntimeBytecode()` uses `unless = "#result == null"` to prevent caching of absent results. However, the method returns `Optional<byte[]>`, and a Spring `Optional` wrapper is **never** `null` — `Optional.empty()` evaluates as non-null. This means every "contract not found" lookup is permanently cached as `Optional.empty()`, allowing an unprivileged attacker to poison the bytecode cache for any contract ID before it is deployed.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** Spring's SpEL `#result` in the `unless` expression refers to the `Optional<byte[]>` object returned by the method, not the value inside it. `Optional.empty()` is a valid non-null object, so `#result == null` is always `false`. The intended guard — "don't cache a miss" — never fires. Every DB miss is cached as `Optional.empty()`.

**Exploit flow:**
1. Hedera contract IDs are assigned sequentially and are publicly observable on-chain. An attacker can predict the next N contract IDs that will be assigned.
2. The attacker sends EVM `eth_call` or `eth_estimateGas` requests targeting those not-yet-deployed contract IDs. Each call internally invokes `ContractBytecodeReadableKVState.readFromDataSource()` → `contractRepository.findRuntimeBytecode(id)`.
3. The DB returns no row; the method returns `Optional.empty()`. Because `Optional.empty() != null`, the `unless` guard passes and `Optional.empty()` is stored in the Caffeine cache under that contract ID.
4. A legitimate user deploys a contract, which is assigned one of those pre-poisoned IDs.
5. Subsequent EVM calls to the newly deployed contract hit the cache and receive `Optional.empty()` → `Bytecode` is `null` → the EVM treats the address as having no code → calls revert or behave as if calling an EOA.
6. The poisoned entry persists until the cache TTL (configured via `cacheProperties.getContract()`) expires.

**Why existing checks fail:** The sole guard is `unless = "#result == null"`. Because the return type is `Optional`, this condition is structurally incapable of detecting an empty result. No secondary validation exists in `ContractBytecodeReadableKVState.readFromDataSource()` before returning `null` to callers.

### Impact Explanation
Any contract deployed after cache poisoning will be unreachable via the mirror-node web3 API for the duration of the cache TTL. All `eth_call`, `eth_estimateGas`, and transaction simulation requests to that contract will fail as if the contract does not exist. For DeFi protocols or bridges that rely on the mirror node for simulation, this causes denial-of-service against newly deployed contracts with no on-chain action required from the attacker beyond sending read-only RPC queries.

### Likelihood Explanation
The attack requires no credentials, no gas, and no privileged access — only the ability to send `eth_call` requests to the public JSON-RPC endpoint. Contract ID prediction is trivial on Hedera (sequential entity IDs). The attack is repeatable and automatable. The only limiting factor is the cache TTL, but the attacker can re-poison on each expiry.

### Recommendation
Fix the `unless` SpEL expression to also exclude empty Optionals:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures that only successful (non-empty) bytecode lookups are cached, and misses always fall through to the database.

### Proof of Concept
1. Observe the current highest entity ID on Hedera testnet (e.g., `0.0.5000`). The next deployed contract will receive `0.0.5001`.
2. Send to the mirror-node web3 JSON-RPC endpoint:
   ```
   POST /api/v1/contracts/call
   { "to": "0x0000000000000000000000000000000000001389", "data": "0x" }
   ```
   (`0x1389` = 5001 in hex, long-zero EVM address form)
3. Observe the response: contract not found / empty bytecode. The `Optional.empty()` is now cached.
4. Deploy any contract on Hedera; it receives ID `0.0.5001`.
5. Immediately repeat the same `eth_call` from step 2. Despite the contract now existing in the DB, the response is still "no bytecode" — served from the poisoned cache.
6. Wait for the cache TTL to expire; the call now succeeds, confirming the issue was cache-based.