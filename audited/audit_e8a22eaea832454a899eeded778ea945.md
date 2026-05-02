### Title
Cache-Amplified DB I/O via Batch Slot Loading in `ContractStateServiceImpl.findStorageBatch()`

### Summary
An unprivileged attacker can populate the per-contract slot-key cache (`slotsPerContract`, max 1500 entries) by issuing 1500 cheap `eth_call` requests against a single contract. Because `contractState` values expire after 2 seconds, every subsequent single `eth_call` to that contract triggers `findStorageBatch()` to issue one DB query with all 1500 cached keys in an `IN` clause — a 1500× amplification of DB I/O per request. This cycle repeats every 2 seconds indefinitely with no per-IP throttle or batch-size cap.

### Finding Description

**Code path:**

`ContractController.call()` → `ContractExecutionService.processCall()` → `ContractStateServiceImpl.findStorage()` → `findStorageBatch()`

**Root cause — `findStorageBatch()` (lines 85–122):** [1](#0-0) 

On every cache miss in `contractStateCache`, the method:
1. Adds the requested key to the per-contract slot-key cache (`contractSlotsCache.putIfAbsent`, line 90).
2. Reads **all** currently cached slot keys for that contract (line 91).
3. Issues a single batch DB query for **all** of them (line 103):

```sql
SELECT slot, value FROM contract_state
WHERE contract_id = :contractId AND slot IN (:slots)
```

There is no cap on the size of `cachedSlots` passed to `findStorageBatch`.

**Cache configuration that enables the attack:** [2](#0-1) 

- `contractState`: `expireAfterWrite=2s` — slot values expire 2 seconds after being written.
- `slotsPerContract`: `maximumSize=1500` — up to 1500 slot keys per contract are retained for 5 minutes.
- `enableBatchContractSlotCaching = true` by default.

**Exploit flow:**

*Phase 1 — Cache poisoning (one-time setup):*
Send 1500 `eth_call` requests, each reading a distinct storage slot of the same contract. Each call misses `contractStateCache`, enters `findStorageBatch()`, and registers its slot key in the per-contract cache. After 1500 requests the per-contract cache is full.

*Phase 2 — Sustained amplification (repeatable every 2 s):*
Wait 2 seconds for all `contractState` entries to expire (`expireAfterWrite=2s`). Send **one** `eth_call` reading any slot of that contract. `findStorage()` misses `contractStateCache` (expired), calls `findStorageBatch()`, which collects all 1500 cached keys and fires:

```sql
SELECT slot, value FROM contract_state
WHERE contract_id = ? AND slot IN (/* 1500 keys */)
```

The 1500 results are written back to `contractStateCache`. Two seconds later they expire again, and the cycle repeats with a single request.

**Why existing checks fail:** [3](#0-2) 

- The **gas throttle** (`gasPerSecond`) is proportional to the declared gas limit of the request, not to the number of DB rows fetched. A minimal-gas `eth_call` (e.g., a single `SLOAD`) consumes negligible gas tokens while triggering a 1500-row DB query.
- The **RPS throttle** (`requestsPerSecond=500`) is a global server-wide bucket, not per-IP. Phase 1 (1500 requests) can be spread over seconds without hitting the global cap.
- The `enableBatchContractSlotCaching` flag is `true` by default and is not a runtime guard against oversized batches.
- There is no maximum batch size enforced inside `findStorageBatch()` before calling `contractStateRepository.findStorageBatch()`. [4](#0-3) 

### Impact Explanation

A single `eth_call` can force the DB to evaluate a `WHERE slot IN (1500 values)` predicate against the `contract_state` table, compared to the expected single-row lookup. With the 2-second TTL, an attacker sustaining ~1 request every 2 seconds against a pre-poisoned contract generates 750 such queries per minute, each scanning up to 1500 index entries. Across multiple contracts (up to 3000 in the outer `contractSlots` cache) this can multiply DB CPU and I/O well beyond the 30% threshold stated in the scope, degrading service for all users. Severity: **Medium–High** (resource exhaustion / availability impact, no data exfiltration).

### Likelihood Explanation

- No authentication or special privilege is required; `eth_call` is a public, unauthenticated endpoint.
- Phase 1 requires 1500 requests, easily achievable from a single IP within seconds at the 500 RPS global cap.
- Phase 2 requires only 1 request per 2-second window, well below any throttle threshold.
- The attack is fully repeatable and requires no on-chain transactions or funds.
- The default configuration (`enableBatchContractSlotCaching=true`, `contractState expireAfterWrite=2s`, `slotsPerContract maximumSize=1500`) makes every default deployment vulnerable.

### Recommendation

1. **Cap the batch size** inside `findStorageBatch()` before calling the repository — e.g., limit `cachedSlots` to a configurable maximum (e.g., 50–100) regardless of how many keys are in the per-contract cache.
2. **Extend `contractState` TTL** or use `expireAfterAccess` instead of `expireAfterWrite` to prevent mass simultaneous expiry of all 1500 entries.
3. **Add per-IP rate limiting** at the HTTP layer (e.g., via a reverse proxy or a per-source bucket in `ThrottleManagerImpl`) so Phase 1 poisoning from a single source is bounded.
4. **Decouple slot-key registration from batch execution**: only add a key to the per-contract cache after its value has been successfully fetched, not before the batch query runs.

### Proof of Concept

```
# Phase 1: populate per-contract slot-key cache (run once)
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"<contract_address>\",
         \"data\":\"0x<getSlot_selector>$(printf '%064x' $i)\",
         \"gas\":100000}" &
done
wait

# Phase 2: trigger 1500-key batch DB query every 2 seconds (sustained)
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"<contract_address>","data":"0x<getSlot_selector>0000...0001","gas":100000}'
  sleep 2
done
```

Each iteration of Phase 2 causes the mirror node to execute:
```sql
SELECT slot, value FROM contract_state
WHERE contract_id = <id> AND slot IN (<1500 32-byte keys>)
```
instead of the expected single-row lookup, amplifying DB I/O by up to 1500×.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-48)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
```
