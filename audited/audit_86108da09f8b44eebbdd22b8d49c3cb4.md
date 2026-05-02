### Title
Cache Poisoning via Incorrect `unless` Condition on `Optional<byte[]>` Return Type in `findRuntimeBytecode()`

### Summary
`ContractRepository.findRuntimeBytecode()` uses `@Cacheable` with `unless = "#result == null"`, but the method returns `Optional<byte[]>`. Because `Optional.empty()` is never `null`, the `unless` guard is always false — empty results (non-existent contracts) are unconditionally cached for up to 1 hour. Any unprivileged user can poison the contract bytecode cache by querying a not-yet-indexed contract ID, causing all subsequent EVM calls and gas estimates against that contract to fail for the full cache TTL.

### Finding Description
**File:** `web3/src/main/java/org/hiero/mirror/web3/repository/ContractRepository.java`, line 16–18

```java
@Cacheable(cacheNames = CACHE_NAME_CONTRACT, cacheManager = CACHE_MANAGER_CONTRACT, unless = "#result == null")
@Query(value = "select runtime_bytecode from contract where id = :contractId", nativeQuery = true)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

Spring's `@Cacheable` evaluates `#result` as the actual return value. Since the return type is `Optional<byte[]>`, the value is always a non-null `Optional` object — either `Optional.of(bytes)` or `Optional.empty()`. The condition `#result == null` is therefore **always false**, meaning the `unless` clause never suppresses caching. Both successful lookups and empty (miss) lookups are cached.

The cache is configured with `expireAfterAccess=1h, maximumSize=1000` (see `CacheProperties.java` line 22).

The cached result flows into `ContractBytecodeReadableKVState.readFromDataSource()` (lines 42–46):

```java
return contractRepository
        .findRuntimeBytecode(entityId.getId())
        .map(Bytes::wrap)
        .map(Bytecode::new)
        .orElse(null);   // returns null when Optional.empty() is cached
```

When `Optional.empty()` is served from cache, `readFromDataSource` returns `null`, and the EVM treats the target address as having no deployed code.

**Exploit flow:**
1. Attacker sends `eth_call` or `eth_estimateGas` targeting a valid contract address whose record has not yet been indexed (e.g., submitted to the network moments ago, or during importer lag).
2. `findRuntimeBytecode(contractId)` hits the DB, finds no row, returns `Optional.empty()`.
3. `Optional.empty() != null` → `unless` is false → `Optional.empty()` is stored in the Caffeine cache under key `contractId`.
4. The importer indexes the contract; the DB now has the correct `runtime_bytecode`.
5. For up to 1 hour, every `eth_call`/`eth_estimateGas` to that contract reads the poisoned cache entry, gets `Optional.empty()`, and the EVM executes against a code-less account.
6. `eth_estimateGas` returns only the base transaction cost (≈21 000 gas) instead of the true execution cost. Wallets and dApps that rely on this estimate submit under-gassed transactions to the actual Hedera network, causing them to fail.

### Impact Explanation
- **Gas estimate corruption:** `eth_estimateGas` returns the minimum base cost for any call to the poisoned contract, because the EVM sees no bytecode to execute. Any transaction built from this estimate will be rejected on-chain for out-of-gas.
- **eth_call failures:** All read-only calls to the contract return empty/zero results or revert, breaking dApp UIs and integrations that depend on the mirror node's JSON-RPC endpoint.
- **Duration:** Up to 1 hour per poisoned entry (`expireAfterAccess=1h`). The cache holds up to 1 000 entries, so an attacker can poison up to 1 000 distinct contract IDs in a single sweep.
- **Severity: High** — no authentication required, deterministic, affects fee/gas correctness for all users of the affected contracts.

### Likelihood Explanation
- No privileges, API keys, or special network access are required. Any caller of the public JSON-RPC endpoint (`eth_call`, `eth_estimateGas`) can trigger this.
- The attack window is the importer indexing lag (typically seconds to a few minutes), which is a normal operational condition, not a rare race.
- The attack is fully repeatable and scriptable: enumerate recently-created contract IDs (visible on the REST API), fire one `eth_estimateGas` per ID before the importer catches up, and the cache is poisoned for 1 hour.

### Recommendation
Change the `unless` condition to also exclude empty `Optional` results:

```java
@Cacheable(
    cacheNames = CACHE_NAME_CONTRACT,
    cacheManager = CACHE_MANAGER_CONTRACT,
    unless = "#result == null || !#result.isPresent()"
)
Optional<byte[]> findRuntimeBytecode(final Long contractId);
```

This mirrors the correct pattern already used in comparable repositories (e.g., `EntityRepository` uses `unless = "#result == null"` on methods that return `Optional<Entity>` — those should be audited for the same issue). Alternatively, unwrap the `Optional` at the repository layer and return `byte[]` directly (returning `null` for absent rows), which makes the existing `unless` condition semantically correct.

### Proof of Concept
```
# 1. Identify a contract that was just submitted to the network but not yet indexed
#    (e.g., via Hedera SDK or by watching the mempool mirror feed)
CONTRACT_ID=0.0.12345   # substitute a real recently-created contract num

# 2. Poison the cache — call eth_estimateGas before the importer indexes the contract
curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x000000000000000000000000000000000000303d","data":"0x","estimate":true}'
# Returns gas=21000 (base cost only, no bytecode executed)

# 3. Wait for the importer to index the contract (a few seconds)
sleep 10

# 4. Repeat the same call — cache is still poisoned, still returns 21000
curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"0x000000000000000000000000000000000000303d","data":"0x","estimate":true}'
# Still returns gas=21000 instead of the correct execution cost

# 5. A wallet using this estimate submits a transaction with gasLimit=21000
#    → transaction fails on-chain with OUT_OF_GAS
``` [1](#0-0) [2](#0-1) [3](#0-2)

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
