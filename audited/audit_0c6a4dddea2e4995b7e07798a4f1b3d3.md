### Title
Cache Saturation Griefing: Attacker-Controlled Slot Keys Force 1500-Entry Batch DB Query Plus Individual Fallback Per Request

### Summary
An unprivileged attacker can saturate the per-contract `slotsPerContract` Caffeine cache (default `maximumSize=1500`) for any target contract by sending 1500 requests with distinct slot keys. Once saturated, every subsequent `findStorage()` call for that contract unconditionally issues a `findStorageBatch()` DB query with a 1500-entry `IN`-list. Under sustained write pressure (write buffer full), Caffeine performs synchronous maintenance and may evict the newly inserted key before `asMap().keySet()` is read, setting `isKeyEvictedFromCache=true` and triggering a second individual `findStorage()` DB query — yielding 2 DB round-trips per request.

### Finding Description

**Cache architecture:**
`cacheManagerSlotsPerContract` is a `CaffeineCacheManager` configured with `expireAfterAccess=5m,maximumSize=1500` (one Caffeine cache instance per contract, created lazily). [1](#0-0) 

Each per-contract cache is retrieved/created at line 86–87: [2](#0-1) 

**Exploit flow in `findStorageBatch()`:**

1. Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — unconditionally inserts the attacker-supplied slot key into the per-contract cache.
2. Line 91: `contractSlotsCache.getNativeCache().asMap().keySet()` — takes a live snapshot of all cached keys.
3. Lines 93–101: iterates the snapshot; if `wrappedKey` is absent, `isKeyEvictedFromCache` stays `true`.
4. Line 103: `findStorageBatch(contractId, cachedSlots)` — issues a DB query with every key in the snapshot (up to 1500 entries in the `IN`-list).
5. Lines 118–119: if `isKeyEvictedFromCache == true`, issues a second individual `findStorage()` DB query. [3](#0-2) [4](#0-3) 

**Root cause — failed assumption:** The design assumes the newly inserted key survives long enough to appear in `asMap().keySet()`. Caffeine's `BoundedLocalCache` uses a fixed-size write buffer (16 slots by default). When the buffer is full — which occurs under sustained write pressure — `scheduleDrainBuffers()` triggers synchronous `performCleanUp()` on the calling thread. During cleanup, the Window TinyLFU policy evicts the lowest-frequency candidate; a brand-new entry (frequency 0) is a prime eviction target. If it is evicted before `asMap()` is read, `isKeyEvictedFromCache` remains `true` and the fallback path fires.

**No authentication or per-contract guard exists** between the HTTP endpoint and `findStorageBatch()`: [5](#0-4) 

The only protection is a global rate bucket (500 req/s, 1 token per request): [6](#0-5) 

### Impact Explanation

Once the per-contract cache is saturated:
- **Every** `findStorage()` call for the target contract that misses `contractStateCache` (TTL 2 s) issues a `SELECT … WHERE slot IN (…)` with up to 1500 bind parameters.
- Under write-buffer saturation, a second individual `SELECT` fires per request.
- At the default 500 req/s global limit, this translates to up to 750,000 slot-lookups/second in the DB for a single targeted contract, sustained indefinitely as long as the attacker keeps the cache full.
- The `contractState` cache TTL is only 2 seconds (`expireAfterWrite=2s`), so cached values expire quickly, ensuring the batch path is hit repeatedly. [7](#0-6) 

### Likelihood Explanation

- **No privileges required.** Any caller of `POST /api/v1/contracts/call` can trigger this.
- **Setup cost is trivial.** 1500 requests at 500 req/s takes ~3 seconds. The attacker can use any 1500 distinct 32-byte slot values (e.g., sequential integers).
- **Self-sustaining.** After saturation, each attacker request with a new slot key both maintains the attack state and triggers the expensive DB path. The `expireAfterAccess=5m` TTL means the cache stays poisoned for 5 minutes of inactivity.
- **Targeted.** The attacker can focus on a single high-traffic contract (e.g., a popular token contract) to maximize collateral impact on legitimate users sharing the same DB connection pool.

### Recommendation

1. **Cap the batch size.** Before calling `findStorageBatch`, truncate `cachedSlots` to a configurable maximum (e.g., 100–200 entries) to bound the `IN`-list size regardless of cache state.
2. **Verify key presence before snapshot.** After `putIfAbsent`, explicitly check `contractSlotsCache.get(wrappedKey)` rather than relying on `asMap()` visibility to determine `isKeyEvictedFromCache`. This eliminates the race with Caffeine's async/sync maintenance.
3. **Per-contract or per-IP rate limiting.** Add a secondary rate limit keyed on `(contractId, callerIP)` to prevent a single source from saturating any one contract's slot cache.
4. **Reduce `maximumSize`.** Lower `slotsPerContract` from 1500 to a smaller value (e.g., 200) to reduce the maximum `IN`-list size and the cost of each batch query.

### Proof of Concept

```
# Step 1: Saturate the per-contract slot cache for contract 0x<TARGET>
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0x<TARGET>\",\"data\":\"0x$(python3 -c "print('2e64cec1' + '${SLOT}')")\",\"gas\":50000}" &
done
wait

# Step 2: Send continuous requests with new slot keys (slot 1501, 1502, ...)
# Each request triggers:
#   (a) findStorageBatch with 1500-entry IN-list
#   (b) Under write-buffer pressure: additional findStorage individual query
for i in $(seq 1501 9999); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0x<TARGET>\",\"data\":\"0x$(python3 -c "print('2e64cec1' + '${SLOT}')")\",\"gas\":50000}"
done
```

Observe DB query logs: each request in Step 2 produces a `SELECT … WHERE slot IN (…)` with 1500 parameters, and intermittently a second single-slot `SELECT`, confirming the 2-DB-query-per-request condition.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-28)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L86-87)
```java
        final var contractSlotsCache = ((CaffeineCache) this.contractSlotsCache.get(
                contractId, () -> cacheManagerSlotsPerContract.getCache(contractId.toString())));
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L90-103)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L118-119)
```java
        if (isKeyEvictedFromCache) {
            return contractStateRepository.findStorage(contractId.getId(), key);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-42)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }
```
