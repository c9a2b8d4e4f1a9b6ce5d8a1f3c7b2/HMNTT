### Title
Incorrect `unless` Condition in `@Cacheable` Causes Indefinite Negative-Result Cache Poisoning in `findRuntimeBytecode()`

### Summary
`findRuntimeBytecode()` returns `Optional<byte[]>`, but its `@Cacheable` annotation uses `unless = "#result == null"`. Because `Optional.empty()` is never `null`, the condition is always `false`, meaning "contract not found" results are unconditionally cached. An unprivileged attacker can pre-query any contract ID before it is indexed, locking the mirror node into returning empty bytecode for that contract for up to one hour — or indefinitely by periodically re-querying.

### Finding Description
**Exact location:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18.

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

**Root cause:** Spring's `@Cacheable` evaluates the `unless` SpEL expression against the actual return value. The method signature guarantees the return value is always an `Optional` object — never `null`. Therefore `#result == null` is always `false`, and every result — including `Optional.empty()` representing "no contract found" — is stored in the cache.

**Cache configuration** (`CacheProperties.java`, line 22):
```
expireAfterAccess=1h, maximumSize=1000
```
`expireAfterAccess` resets the TTL on every read, so a poisoned entry survives indefinitely as long as it is periodically accessed.

**Exploit flow:**
1. Attacker sends any unauthenticated web3 JSON-RPC request (e.g., `eth_getCode`, `eth_call`) targeting a contract address whose numeric entity ID is known or guessable but not yet indexed by the importer.
2. `ContractBytecodeReadableKVState.readFromDataSource()` calls `contractRepository.findRuntimeBytecode(entityId.getId())`.
3. The DB returns no row → Spring Data JPA returns `Optional.empty()`.
4. `Optional.empty() != null` → `unless` is `false` → `Optional.empty()` is written to the Caffeine cache under key `contractId`.
5. The importer later indexes the contract and writes its `runtime_bytecode` to the DB.
6. All subsequent calls to `findRuntimeBytecode(contractId)` hit the cache and return `Optional.empty()` — the DB is never re-queried.
7. `readFromDataSource()` maps `Optional.empty()` to `null` via `.orElse(null)`, so the EVM sees no bytecode for the contract.

**Why existing checks fail:** The `unless` guard was intended to prevent caching of absent results, but it tests for Java `null` rather than `Optional.isEmpty()`. No other invalidation or eviction mechanism exists for this cache entry.

### Impact Explanation
Any contract that an attacker queries before the mirror node indexes it will appear to have no bytecode for up to one hour (or indefinitely with periodic re-queries). `eth_getCode` returns `0x`; `eth_call` and `eth_estimateGas` behave as if the target is an EOA, causing all calls to revert or return empty data. This breaks DeFi integrations, wallets, and tooling that rely on the mirror node's web3 API for contract interaction. The attacker can also fill all 1,000 cache slots with poisoned entries, evicting legitimate bytecode and degrading service for all contracts.

### Likelihood Explanation
No authentication or rate-limiting is required. The attacker only needs to know (or enumerate) a contract's numeric entity ID before the importer finishes indexing it — a narrow but realistic window given that Hedera entity IDs are sequential and publicly observable on-chain. The attack is repeatable, low-cost, and requires only standard HTTP requests to the public web3 endpoint.

### Recommendation
Fix the `unless` condition to exclude empty Optionals from caching:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
```

This ensures only successful (non-empty) bytecode lookups are cached, while "not found" results always fall through to the database on the next request.

### Proof of Concept
```bash
# 1. Identify a contract entity ID that is about to be deployed (e.g., ID 12345)
#    but has not yet been indexed by the mirror node importer.

# 2. Pre-poison the cache with an empty result:
curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getCode",
       "params":["0x000000000000000000000000000000000000303900","latest"],
       "id":1}'
# Returns: {"result":"0x"}  ← empty, and now cached

# 3. Wait for the contract to be deployed and indexed by the importer.

# 4. Re-query — cache still returns empty despite bytecode now existing in DB:
curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","method":"eth_getCode",
       "params":["0x000000000000000000000000000000000000303900","latest"],
       "id":2}'
# Returns: {"result":"0x"}  ← still empty; real bytecode is invisible for up to 1 hour

# 5. Repeat step 4 every ~55 minutes to keep the poisoned entry alive indefinitely
#    (expireAfterAccess resets the TTL on each read).
```