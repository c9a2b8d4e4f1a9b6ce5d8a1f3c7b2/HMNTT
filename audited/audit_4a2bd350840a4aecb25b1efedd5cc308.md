### Title
Cache-Bypass Batch Query Amplification via `expireAfterWrite=2s` on `contractStateCache`

### Summary
The `contractStateCache` is configured with `expireAfterWrite=2s`, causing all cached slot values to expire unconditionally every 2 seconds regardless of access frequency. An unprivileged attacker who pre-populates the per-contract slot key cache (`slotsPerContract`, TTL 5 minutes) can then send one request every ~2 seconds to guarantee a cache miss, which triggers `findStorageBatch()` — a DB query that fetches **all** cached slot keys for that contract in a single `IN` clause. This creates a sustained, low-rate, high-amplification DB load attack requiring no credentials.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70): [1](#0-0) 

On every call, line 63 checks `contractStateCache`. Because the cache is configured with `expireAfterWrite=2s`: [2](#0-1) 

…entries expire 2 seconds after being written, regardless of how frequently they are accessed. A request arriving ≥2s after the last write always gets a cache miss and falls through to `findStorageBatch()`.

`findStorageBatch()` (lines 85–122) then:
1. Retrieves the per-contract slot key cache (TTL `expireAfterAccess=5m`, max 1500 slots): [3](#0-2) 

2. Collects **all** cached slot keys for the contract and issues a single batch DB query for all of them: [4](#0-3) 

3. Writes results back to `contractStateCache` (resetting the 2s write timer): [5](#0-4) 

**Root cause and failed assumption:** The design assumes the batch preload reduces DB pressure by amortizing queries across many slots. The failed assumption is that `contractStateCache` entries will remain warm between requests. Because `expireAfterWrite=2s` is unconditional, an attacker who controls request timing can guarantee every request is a cache miss, turning the batch preload into an amplification multiplier: **1 HTTP request → 1 DB query for up to 1500 slots**.

The `slotsPerContract` cache (TTL `expireAfterAccess=5m`) keeps slot keys alive as long as the attacker keeps accessing them, while `contractStateCache` (TTL `expireAfterWrite=2s`) continuously discards the values: [6](#0-5) 

### Impact Explanation

- **Amplification factor:** Up to 1500× per contract (`slotsPerContract` max size). One HTTP request triggers a `SELECT slot, value FROM contract_state WHERE contract_id = ? AND slot IN (...)` with up to 1500 bind parameters.
- **Multi-contract scaling:** `contractSlots` holds up to 3000 contracts. An attacker targeting K contracts at 0.5 req/s each generates K × 1500 slot lookups per 2-second window. At K=300 contracts, that is 225,000 slot DB lookups every 2 seconds from just 150 req/s — well within the global rate limit.
- **DB resource consumption:** Each batch query is a non-trivial indexed scan on `contract_state`. Sustained amplified load can saturate DB connection pools, increase query latency for all users, and degrade overall mirror node availability.

### Likelihood Explanation

- **No authentication required.** The `/api/v1/contracts/call` endpoint is public.
- **Rate limiter is insufficient.** The global `requestsPerSecond=500` limit: [7](#0-6) 
…is a global token bucket, not per-IP. The attack only needs 0.5 req/s per contract, far below the threshold. There is no per-source-IP throttle in the codebase.
- **Gas throttle is irrelevant.** `scaleGas()` returns 0 for gas ≤ 10,000: [8](#0-7) 
A minimal `eth_call` (gas=21,000) consumes only 2 gas tokens against a 750,000,000 token/s budget.
- **Repeatable and automatable.** A simple script sending one `eth_call` per 2.1 seconds per contract address is sufficient. No special knowledge of contract internals is needed — the attacker only needs to have previously queried different slots to populate the `slotsPerContract` cache.

### Recommendation

1. **Switch `contractState` to `expireAfterAccess`** instead of `expireAfterWrite`. This allows actively-used entries to remain warm and only evicts genuinely idle entries, eliminating the predictable 2s expiry window.
2. **Bound batch query size independently of cache size.** In `findStorageBatch()`, cap `cachedSlots` to a configurable maximum (e.g., 50–100) before issuing the `IN` query, regardless of how many keys are in the per-contract slot cache.
3. **Add per-source-IP rate limiting** at the ingress/filter layer to prevent a single client from sustaining amplified load across many contracts.
4. **Consider lazy eviction from `slotsPerContract`:** When `contractStateCache` entries expire, also evict the corresponding keys from the per-contract slot cache so stale slot keys do not accumulate and inflate future batch queries.

### Proof of Concept

**Preconditions:** Mirror node is running with default cache configuration. Target contract `0xCONTRACT` has at least N storage slots (N ≥ 100 for meaningful amplification).

**Step 1 — Populate the per-contract slot cache (one-time setup):**
```bash
# Send N distinct eth_call requests that read different storage slots of the contract.
# Each call causes findStorageBatch() to add a new slot key to the slotsPerContract cache.
for i in $(seq 1 1500); do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0xCONTRACT\",\"data\":\"0x<selector_reading_slot_$i>\",\"gas\":50000}"
done
# After this, the slotsPerContract cache for 0xCONTRACT holds up to 1500 slot keys (TTL 5m).
```

**Step 2 — Sustained cache-bypass loop:**
```bash
# Send one request every 2.1 seconds. Each request:
#   - Misses contractStateCache (expired after 2s)
#   - Triggers findStorageBatch() querying all 1500 cached slots from DB
#   - Re-populates contractStateCache (resets 2s timer)
#   - Keeps slotsPerContract alive (resets 5m access timer)
while true; do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0xCONTRACT","data":"0x<any_storage_read_selector>","gas":50000}'
  sleep 2.1
done
```

**Observed effect:** Each iteration of the loop causes `ContractStateRepository.findStorageBatch()` to execute `SELECT slot, value FROM contract_state WHERE contract_id = ? AND slot IN (?, ?, ..., ?)` with 1500 bind parameters. DB CPU and I/O increase proportionally. Scaling to 10 concurrent contracts (5 req/s total) produces 15,000 slot lookups per 2-second window from a single attacker staying well under the 500 req/s global rate limit.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L58-70)
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
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L86-91)
```java
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
        final var wrappedKey = ByteBuffer.wrap(key);
        // Cached slot keys for contract, whose slot values are not present in the contractStateCache
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
        final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L93-103)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L106-113)
```java
        for (final var contractSlotValue : contractSlotValues) {
            final byte[] slotKey = contractSlotValue.getSlot();
            final byte[] slotValue = contractSlotValue.getValue();
            contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);

            if (Arrays.equals(slotKey, key)) {
                cachedValue = slotValue;
            }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```
