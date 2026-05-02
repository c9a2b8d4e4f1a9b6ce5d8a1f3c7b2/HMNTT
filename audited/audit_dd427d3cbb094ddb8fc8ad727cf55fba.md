### Title
Cache-Amplified Database DoS via Unbounded Batch Slot Query Accumulation in `findStorageBatch()`

### Summary
`ContractStateServiceImpl.findStorageBatch()` accumulates every distinct slot key ever requested for a given contract into a per-contract Caffeine cache (`slotsPerContract`, TTL 5 min, max 1500 entries). On every cache miss in `contractStateCache` (TTL 2 s), it issues a single SQL `IN`-clause query containing **all** accumulated slot keys for that contract — up to 1500. An unprivileged attacker can prime this cache for many contracts with arbitrary (non-existent) slot keys, then repeatedly trigger 1500-slot batch queries across all primed contracts, multiplying database work by up to 1500× per request with no per-user rate control.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (line 63–69) checks `contractStateCache` (TTL `expireAfterWrite=2s`). On any miss it calls `findStorageBatch()` (line 85–122).

Inside `findStorageBatch()`:
- Line 86–87: retrieves or lazily creates a per-contract `CaffeineCache` via `cacheManagerSlotsPerContract.getCache(contractId.toString())`. This named cache is stored permanently in `CaffeineCacheManager`'s internal `ConcurrentHashMap` and is **never evicted** from the manager itself.
- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — unconditionally registers the requested slot key into the per-contract cache.
- Line 91–101: collects **all** currently cached slot keys for this contract into `cachedSlots`.
- Line 103: issues `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — a native SQL query `WHERE slot IN (:slots)` with up to 1500 parameters.

**Root cause — two mismatched TTLs with no IN-clause size cap:**

| Cache | TTL | Max size |
|---|---|---|
| `contractStateCache` (values) | `expireAfterWrite=2s` | 25,000 |
| `slotsPerContract` (keys) | `expireAfterAccess=5m` | 1,500/contract |

Slot keys accumulate for 5 minutes; their corresponding values expire every 2 seconds. After each 2-second window, every new request to a primed contract misses `contractStateCache` and triggers a full 1500-slot IN query. There is no cap on the IN-clause size before the DB call is issued.

**Why existing checks fail:**

The only throttle is a global token-bucket at `requestsPerSecond=500` (no per-IP, no per-contract, no per-user limit). The gas throttle (`gasPerSecond`) applies to EVM execution gas, not to the number of DB rows scanned. The `contractSlots` outer cache (`maximumSize=3000`) limits active outer entries but does **not** evict the underlying per-contract caches from `cacheManagerSlotsPerContract` — those persist indefinitely in the `CaffeineCacheManager`'s internal map.

**Exploit flow:**

1. **Prime phase**: Attacker sends 1,500 requests to contract A, each with a distinct (fabricated, non-existent) 32-byte slot key. Each request adds one key to A's `slotsPerContract` cache. Repeat for contracts B, C, … up to N contracts.
2. **Trigger phase**: After ≥2 seconds (contractStateCache expiry), attacker sends one request per primed contract. Each request misses `contractStateCache`, enters `findStorageBatch()`, and issues a `WHERE slot IN (…1500 params…)` query against `contract_state`.
3. **Sustained amplification**: Repeat trigger phase every 2 seconds. The slot keys remain in cache for 5 minutes, so no re-priming is needed.

### Impact Explanation

**Baseline DB work**: 500 req/s × 1 slot lookup = 500 slot lookups/s.

**Under attack**: 500 req/s × 1,500 slot lookups = 750,000 slot lookups/s — a **1,500× amplification** in DB row scans, far exceeding the 30% threshold. Each IN-clause query also forces the DB planner to evaluate a 1,500-element parameter list, increasing query planning overhead. With N primed contracts and concurrent requests, the DB connection pool and I/O bandwidth are saturated. The `db.statementTimeout=3000ms` provides partial protection but does not prevent the amplification from accumulating across many concurrent queries before timeouts fire.

### Likelihood Explanation

No authentication, no special privilege, and no on-chain cost is required. The priming phase costs N×1,500 HTTP requests; at the global limit of 500 req/s, priming 100 contracts takes 300 seconds. The attack is fully repeatable every 2 seconds thereafter. Any public Hedera mirror-node web3 endpoint is reachable by any internet user. The attack is scriptable with a simple HTTP client loop.

### Recommendation

1. **Cap the IN-clause size before the DB call**: In `findStorageBatch()`, limit `cachedSlots` to a configurable maximum (e.g., 100) before passing to `findStorageBatch`. Discard or ignore excess keys.
2. **Align cache TTLs**: Either extend `contractStateCache` TTL to match `slotsPerContract` (5 min), or shorten `slotsPerContract` TTL to match `contractStateCache` (2 s), so that slot keys do not outlive their values.
3. **Add per-IP or per-caller rate limiting** at the HTTP layer (e.g., via a reverse proxy or Spring filter) to prevent a single source from priming many contracts.
4. **Evict per-contract caches from `cacheManagerSlotsPerContract`** when the corresponding entry is evicted from the outer `contractSlots` cache, to prevent unbounded growth of named caches in the `CaffeineCacheManager`.

### Proof of Concept

```python
import requests, threading, os

BASE = "http://<mirror-node>/api/v1/contracts/call"
CONTRACT_A = "0x000000000000000000000000000000000000AAAA"

# Phase 1: prime contract A with 1500 distinct slot keys
# Each eth_call reads storage slot i via a SLOAD opcode
for i in range(1500):
    slot = hex(i).zfill(66)   # 32-byte slot key
    requests.post(BASE, json={
        "to": CONTRACT_A,
        "data": "0x" + "20965255" + slot[2:],  # getStorageAt(slot)
        "block": "latest"
    })

import time; time.sleep(3)  # wait for contractStateCache to expire

# Phase 2: trigger 1500-slot IN query every 2 seconds
while True:
    requests.post(BASE, json={
        "to": CONTRACT_A,
        "data": "0x20965255" + "00" * 32,
        "block": "latest"
    })
    # Each call above triggers: SELECT slot,value FROM contract_state
    #   WHERE contract_id=? AND slot IN (slot_0, slot_1, ..., slot_1499)
    time.sleep(2)
```

Repeat Phase 1 for N contracts and fire N concurrent threads in Phase 2 to multiply DB load by N×1500. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L58-69)
```java
    public Optional<byte[]> findStorage(final EntityId contractId, final byte[] key) {
        if (!cacheProperties.isEnableBatchContractSlotCaching()) {
            return contractStateRepository.findStorage(contractId.getId(), key);
        }

        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
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
