### Title
Unauthenticated DB Amplification via `findStorage()` Batch Query Growth Bypasses Per-Node Gas Throttle

### Summary
The gas throttle in `ThrottleManagerImpl` is a per-node, in-memory token bucket that limits gas consumption before EVM execution but places no bound on the number of database queries generated per unit of gas consumed. A contract that performs many unique SLOAD operations causes `ContractStateServiceImpl.findStorage()` to issue a growing `findStorageBatch` query on every cache miss — each query including all previously accumulated slot keys (up to 1,500). At the default throttle of 1,500,000,000 gas/s with `maxGasLimit=15,000,000`, an unprivileged attacker can sustain 100 requests/second, each generating up to ~7,142 DB queries, producing a sustained load that can saturate the shared PostgreSQL backend and degrade all mirror nodes that share it.

### Finding Description

**Exact code path:**

`ContractController.call()` → `ThrottleManagerImpl.throttle()` (gas consumed pre-execution) → `ContractExecutionService.processCall()` → EVM executes SLOADs → `ContractStorageReadableKVState.readFromDataSource()` → `ContractStateServiceImpl.findStorage()` → `ContractStateServiceImpl.findStorageBatch()` → `ContractStateRepository.findStorageBatch()` (uncached DB query).

**Root cause — gas throttle does not bound DB queries per gas unit:**

`ThrottleManagerImpl.throttle()` deducts `scaleGas(request.getGas())` tokens from the in-memory `gasLimitBucket` before execution begins:

```java
// ThrottleManagerImpl.java line 40
} else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
    throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
}
```

`scaleGas` divides by `GAS_SCALE_FACTOR = 10_000`:

```java
// ThrottleProperties.java lines 42-47
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) { return 0L; }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
```

With `gasPerSecond = 1,500,000,000` (docs default), the bucket holds `1,500,000,000 / 10,000 = 150,000` tokens. Each request at `gas = 15,000,000` consumes `1,500` tokens → **100 requests/second** pass the throttle.

**DB amplification in `findStorageBatch()`:**

`findStorage()` checks `contractStateCache` (TTL = 2 s). On a miss it calls `findStorageBatch()`:

```java
// ContractStateServiceImpl.java lines 85-122
private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
    final var contractSlotsCache = ...
    contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);          // accumulate key
    final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet(); // ALL keys
    ...
    final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots); // DB hit
```

`findStorageBatch` on the repository has **no `@Cacheable` annotation** — it always hits the DB:

```java
// ContractStateRepository.java lines 23-28
@Query(value = "select slot, value from contract_state where contract_id = :contractId and slot in (:slots)", nativeQuery = true)
List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```

Each unique SLOAD in a request that misses `contractStateCache` triggers one `findStorageBatch` call whose `IN (...)` clause grows with every new slot key accumulated in `slotsPerContract` (max 1,500 entries, `expireAfterAccess=5m`). For a contract with 1,500 pre-seeded unique slots, every cache-miss SLOAD issues a query with 1,500 keys.

**Gas restore does not help the attacker here — it hurts the defender:**

```java
// ContractCallService.java lines 140-151
private void restoreGasToBucket(EvmTransactionResult result, long gasLimit) {
    final var gasLimitToRestoreBaseline = (long) (gasLimit * throttleProperties.getGasLimitRefundPercent() / 100f);
    ...
    throttleManager.restore(Math.min(gasRemaining, gasLimitToRestoreBaseline));
}
```

With `gasLimitRefundPercent = 100` (default), if the attacker crafts a contract that consumes exactly 15M gas (all SLOADs), `gasRemaining = 0` and `restore(0)` is called — nothing is returned to the bucket. The attacker sustains the full 100 req/s indefinitely.

**The throttle is per-node and in-memory:**

```java
// ThrottleConfiguration.java lines 34-45
@Bean(name = GAS_LIMIT_BUCKET)
Bucket gasLimitBucket() {
    long gasLimit = throttleProperties.getGasPerSecond();
    final var limit = Bandwidth.builder().capacity(gasLimit).refillGreedy(gasLimit, Duration.ofSeconds(1)).build();
    return Bucket.builder().withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED).addLimit(limit).build();
}
```

This is a JVM-local `Bucket`. Each mirror node has its own independent bucket. There is no per-IP rate limiting anywhere in the controller or filter chain. An attacker targeting N nodes multiplies the DB load by N.

**`contractState` cache TTL = 2 s creates a repeating attack window:**

```java
// CacheProperties.java line 28
private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

Every 2 seconds the value cache expires. The slot-key cache (`slotsPerContract`, TTL = 5 min) remains warm. So every 2 seconds the attacker's requests re-trigger the full batch-query load against a cold value cache.

### Impact Explanation

At 100 req/s with a contract that accesses 1,500 unique storage slots per call (cost: 1,500 × 2,100 = 3,150,000 gas, well within 15M):

- **DB queries per second**: 100 req/s × 1,500 `findStorageBatch` calls/req = **150,000 DB queries/second**, each with an `IN` clause of up to 1,500 byte-array keys.
- The shared PostgreSQL backend (`statementTimeout = 3,000 ms`) will begin queuing and timing out queries, causing cascading failures across all mirror nodes that share the same DB instance.
- Because the throttle is per-node and the DB is shared, a single attacker targeting one node can degrade all nodes. Targeting multiple nodes multiplies the effect linearly.
- No authentication, API key, or account is required.

### Likelihood Explanation

- **Precondition**: A contract with many storage slots exists on the network (trivially true on mainnet/testnet; attacker can also deploy one).
- **Skill required**: Sending HTTP POST requests to `/api/v1/contracts/call` with `gas: 15000000` and calldata that loops over SLOAD opcodes. This is standard Solidity/web3 tooling.
- **Repeatability**: Fully automated and repeatable. The attack sustains itself as long as the attacker sends requests at 100 req/s (or distributes across nodes).
- **No cost**: `eth_call` is a read-only simulation; no on-chain transaction or HBAR fee is required.

### Recommendation

1. **Add per-IP (or per-connection) rate limiting** at the HTTP layer (e.g., Spring `HandlerInterceptor` or a reverse-proxy rule) so a single source cannot consume the entire per-node gas budget.
2. **Limit DB queries per request**, not just gas: track the number of `findStorageBatch` calls within a single `ContractCallContext` and cap it (e.g., 50 batch queries per request).
3. **Add `@Cacheable` to `findStorageBatch`** or cache its results at the service layer with a short TTL to prevent repeated identical queries across concurrent requests.
4. **Distribute the gas throttle** using a shared store (Redis/Hazelcast) so the budget is enforced across all nodes, not per-node.
5. **Reduce `gasLimitRefundPercent`** below 100 so that gas-exhausting requests return tokens to the bucket, reducing the effective sustained request rate for worst-case callers.

### Proof of Concept

```
# 1. Deploy a Solidity contract that reads N unique storage slots in a loop:
#    for (uint i = 0; i < 1500; i++) { assembly { pop(sload(i)) } }
#    Deploy to testnet, note contract address.

# 2. Encode the call to the loop function (e.g., using cast or web3.py).

# 3. Send 100 requests/second to a single mirror node:
while true; do
  for i in $(seq 1 100); do
    curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
      -H 'Content-Type: application/json' \
      -d '{"to":"<contract>","gas":15000000,"data":"<loop_calldata>"}' &
  done
  sleep 1
done

# 4. Observe: PostgreSQL CPU/IO spikes, query queue depth grows,
#    statement timeouts begin firing, all mirror nodes sharing the DB
#    return errors or slow responses within seconds.
```