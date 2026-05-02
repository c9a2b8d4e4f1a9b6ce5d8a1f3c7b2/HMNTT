### Title
Uncached Per-SLOAD DB Query on Historical Calls Enables DB Connection Pool Exhaustion via Unprivileged `eth_call`

### Summary
Any unauthenticated caller can submit a `POST /api/v1/contracts/call` request targeting a historical block with a SLOAD-heavy contract function. For historical queries, `ContractStorageReadableKVState.readFromDataSource()` routes every single SLOAD through `ContractStateServiceImpl.findStorageByBlockTimestamp()`, which issues one uncached, unbatched SQL query per slot. The gas-based throttle limits total gas per second but does not bound the number of concurrent DB connections held, allowing an attacker to exhaust the database connection pool and deny service to all users.

### Finding Description

**Exact code path:**

`ContractController.call()` (line 38–51) → `ThrottleManagerImpl.throttle()` (line 37–48) → `ContractExecutionService.processCall()` → `ContractCallService.doProcessCall()` → `TransactionExecutionService.execute()` (line 92) → EVM execution → per-SLOAD → `ContractStorageReadableKVState.readFromDataSource()` (line 32–48) → `ContractStateServiceImpl.findStorageByBlockTimestamp()` (line 73–76) → `ContractStateRepository.findStorageByBlockTimestamp()` (line 44–54, one SQL per slot, no cache).

**Root cause — failed assumption in `ContractStorageReadableKVState.readFromDataSource()`:**

```java
// ContractStorageReadableKVState.java lines 41-44
return timestamp
    .map(t -> contractStateService.findStorageByBlockTimestamp(   // historical path
            entityId, Bytes32.wrap(keyBytes).trimLeadingZeros().toArrayUnsafe(), t))
    .orElse(contractStateService.findStorage(entityId, keyBytes)) // latest path (batched+cached)
```

When `timestamp` is present (any historical block), the call goes to `findStorageByBlockTimestamp`. `ContractStateServiceImpl.findStorageByBlockTimestamp()` (line 73–76) is a one-liner that calls the repository directly with **no Caffeine cache, no batch accumulation**:

```java
// ContractStateServiceImpl.java lines 73-76
public Optional<byte[]> findStorageByBlockTimestamp(
        final EntityId entityId, final byte[] slotKeyByteArray, final long blockTimestamp) {
    return contractStateRepository.findStorageByBlockTimestamp(entityId.getId(), slotKeyByteArray, blockTimestamp);
}
```

The repository query (lines 44–54) hits `contract_state_change` with an `ORDER BY consensus_timestamp DESC LIMIT 1` per slot — one round-trip per SLOAD.

By contrast, the latest-block path in `ContractStateServiceImpl.findStorage()` (lines 58–70) uses a Caffeine cache and a batch query (`findStorageBatch`), dramatically reducing DB round-trips.

**Gas throttle is insufficient:**

`ThrottleManagerImpl.throttle()` (line 40) consumes `scaleGas(request.getGas())` tokens:

```java
// ThrottleProperties.java lines 42-47
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) { // 10_000
        return 0L;                 // ← gas ≤ 10,000 consumes ZERO tokens
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
```

At `maxGasLimit = 15,000,000` (EvmProperties line 69), `scaleGas(15_000_000)` = 1,500 tokens. Default `gasPerSecond = 7,500,000,000` → scaled bucket capacity = 750,000 tokens/second → 500 requests/second at max gas. This aligns with `requestsPerSecond = 500`.

Each 15 M-gas request can execute ≈ 7,142 cold SLOADs (15,000,000 / 2,100 gas per EIP-2929 cold access). On the historical path each SLOAD is one DB query → **500 req/s × 7,142 queries/req = ~3.57 M DB queries/second**. A typical PostgreSQL pool of 10–50 connections cannot sustain this. Requests hold connections for up to the 10-second `requestTimeout`, causing pool starvation for all other users.

Additionally, `scaleGas` returns 0 for gas ≤ 10,000, meaning those requests consume **no gas-bucket tokens at all** and are only bounded by the 500 RPS rate limit.

### Impact Explanation
Complete denial of service for the web3 module. Once the DB connection pool is exhausted, all contract calls, token queries, and balance lookups fail. The attack targets the shared PostgreSQL connection pool, so it affects every downstream consumer of the mirror node's web3 API. Recovery requires the attacker to stop sending requests and the pool to drain, which can take up to `requestTimeout` (10 s) per in-flight request.

### Likelihood Explanation
No authentication, no per-IP rate limiting, and no per-user quota exist. Any internet-accessible deployment is reachable. The attacker only needs to know (or discover) the address of any storage-heavy contract (e.g., any AMM, lending protocol, or the publicly documented `SlotContract`/`SlotContractCaller` test contracts) and the ABI selector for a storage-reading function. The attack is trivially scriptable with `curl` or any HTTP client at 500 req/s. It is repeatable indefinitely.

### Recommendation

1. **Add per-SLOAD query caching for historical calls.** Introduce a request-scoped cache (keyed on `(contractId, slot, blockTimestamp)`) inside `ContractStateServiceImpl.findStorageByBlockTimestamp()` so repeated reads of the same slot within one EVM execution do not re-query the DB.

2. **Add a historical-batch query path.** Mirror the `findStorageBatch` pattern for `contract_state_change`: accumulate slot keys seen during a single EVM execution and resolve them in one `IN (...)` query at the end, or use a pre-fetch strategy.

3. **Enforce a per-request SLOAD (DB query) cap.** Track the number of storage reads in `ContractCallContext` and abort execution (out-of-gas or custom error) once a configurable limit is reached.

4. **Add per-IP / per-source rate limiting** at the ingress layer (reverse proxy or Spring filter) to prevent a single client from consuming the full 500 RPS budget.

5. **Fix the `scaleGas` zero-token bypass.** Requests with gas ≤ 10,000 should consume at least 1 token from the gas bucket to prevent free-riding on the rate limit.

### Proof of Concept

```bash
# 1. Identify any storage-heavy contract on the target network.
#    The project's own SlotContractCaller (heavyReadBothHalves = 3000 SLOADs) is documented.
CONTRACT="0x00000000000000000000000000000000008f005f"
CALLDATA="0x523adad6"   # heavyReadBothHalves()
HISTORICAL_BLOCK="0x1"  # any past block forces the uncached path

# 2. Flood at 500 req/s (matches the rate limit) from a single host:
for i in $(seq 1 500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"$CONTRACT\",\"data\":\"$CALLDATA\",\"gas\":15000000,\"block\":\"$HISTORICAL_BLOCK\"}" &
done
wait

# 3. Repeat in a tight loop. Within seconds the PostgreSQL connection pool
#    is exhausted; all subsequent requests return 500 / connection timeout.
```

Each iteration of the loop triggers ≈ 3,000 uncached `findStorageByBlockTimestamp` SQL queries. With 500 concurrent requests the pool (typically 10–50 connections) is saturated, and legitimate traffic is denied.