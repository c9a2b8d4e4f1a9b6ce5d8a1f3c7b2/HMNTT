### Title
Unprivileged Cache Exhaustion of `cacheManagerContractState` via High-Slot-Count Contract Calls

### Summary
The `contractState` Caffeine cache (`maximumSize=25000`, `expireAfterWrite=2s`) is a single global, unisolated store keyed by `(contractId, slotKey)`. Any unauthenticated caller can issue a small number of contract-call requests that each trigger thousands of distinct SLOAD operations, filling all 25,000 cache slots with attacker-controlled entries. Because Caffeine evicts by LRU when the limit is reached, legitimate users' entries are continuously displaced, forcing every subsequent `findStorage` call to fall back to a synchronous DB query for the entire duration of the attack.

### Finding Description

**Exact code path:**

`EvmConfiguration.java` lines 83–89 configure the cache with no per-user partitioning:
```java
@Bean(CACHE_MANAGER_CONTRACT_STATE)
CacheManager cacheManagerContractState() {
    final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
    caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
    caffeineCacheManager.setCacheSpecification(cacheProperties.getContractState()); // "expireAfterWrite=2s,maximumSize=25000"
    return caffeineCacheManager;
}
```

`CacheProperties.java` line 28 sets the limit:
```java
private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

`ContractStateServiceImpl.java` lines 103–113 populate the cache once per slot returned by the batch DB query — one entry per unique `(contractId, slotKey)` pair:
```java
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
for (final var contractSlotValue : contractSlotValues) {
    contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);
}
```

`ContractStorageReadableKVState.java` line 44 calls `contractStateService.findStorage(...)` for every SLOAD opcode executed during EVM simulation — one call per unique storage slot accessed.

**Root cause:** The cache is a single JVM-wide flat map. There is no per-IP, per-caller, or per-contract quota. The global throttle (`ThrottleManagerImpl.java`) enforces only a shared 500 req/s and a shared gas-per-second budget — neither of which prevents a single caller from filling the cache.

**Exploit flow:**
1. With `maxGasLimit = 15,000,000` and a cold SLOAD costing 2,100 gas, one request can trigger ≈7,142 distinct `findStorage` calls.
2. Four such requests (≈28,000 unique slots) exceed `maximumSize=25000`, causing Caffeine to evict the oldest entries.
3. The attacker repeats this every 2 seconds (matching `expireAfterWrite`) to keep the cache permanently saturated.
4. Every `findStorage` call for a legitimate user misses the cache and falls through to `contractStateRepository.findStorageBatch` or `findStorage` (DB query).

**Why existing checks fail:**
- The global rate limiter (`rateLimitBucket`, 500 req/s) is shared across all users. The attacker consumes only 4 of those 500 slots per second — 0.8% of capacity — while filling 100% of the cache.
- There is no per-IP or per-source rate limiting anywhere in the web3 throttle stack (`ThrottleManagerImpl`, `ThrottleConfiguration`, `RequestProperties`).
- The `request[]` filter list defaults to empty (`List.of()`), so no per-caller REJECT/THROTTLE rules are applied by default.

### Impact Explanation
Every legitimate `eth_call` / `eth_estimateGas` request that reads contract storage will miss the cache and issue a synchronous PostgreSQL query. Under sustained attack this multiplies DB load proportionally to the number of concurrent legitimate users, degrading response latency and potentially exhausting the DB connection pool. The `statementTimeout=3000ms` setting means requests that queue behind DB load will time out and return errors to end users. This is a denial-of-service against the read path of all contracts, not just the attacker's.

### Likelihood Explanation
No special privileges, tokens, or on-chain funds are required. Any caller with network access to the JSON-RPC endpoint can craft a `eth_call` targeting a contract with many storage slots (or a contract they deploy themselves that reads from a large mapping). The attack is repeatable, automatable, and requires only ~4 HTTP requests per 2-second window to maintain full cache saturation. The 2-second TTL does not mitigate the issue — it merely sets the minimum attack refresh rate.

### Recommendation
1. **Per-contract or per-caller cache partitioning**: Enforce a maximum number of cache entries per `contractId` so one contract cannot crowd out others.
2. **Per-IP rate limiting**: Add a per-source-IP token bucket (e.g., via a servlet filter or Spring Security) in addition to the existing global bucket.
3. **Increase `maximumSize` proportionally** or switch to a `maximumWeight`-based policy that accounts for the number of slots per contract.
4. **Cap SLOAD count per request**: Enforce a hard limit on the number of distinct storage slots that can be accessed in a single simulated call, independent of the gas limit.
5. **Short-circuit batch size**: In `findStorageBatch`, cap `cachedSlots` to a configurable maximum (e.g., 500) to bound the number of cache entries written per request.

### Proof of Concept
```
# Step 1: Deploy (or identify) a contract with ≥25,000 distinct storage slots.
# Step 2: Craft calldata that executes SLOAD on each slot (e.g., a loop reading a large mapping).
# Step 3: Send 4 concurrent eth_call requests with gas=15000000:
for i in {1..4}; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"<calldata_reading_7142_unique_slots>","to":"<contract>","gas":15000000,"estimate":false}' &
done
wait
# Step 4: Immediately send a legitimate eth_call for a different contract and measure latency.
# Expected: response time increases significantly due to DB fallback; cache hit rate drops to ~0%.
# Step 5: Repeat steps 3-4 every 2 seconds to sustain the attack.
```