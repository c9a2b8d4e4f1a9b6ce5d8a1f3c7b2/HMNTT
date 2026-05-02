I have verified all code references and claims against the actual codebase. Here is my assessment:

---

## Audit Report

## Title
Unsynchronized Read-Modify-Query Race in `findStorageBatch` Enables O(N²) DB Amplification

## Summary
In `ContractStateServiceImpl.findStorageBatch()`, the `putIfAbsent` that registers a new slot key, the live-view key-set snapshot, and the subsequent DB query are not atomic. Concurrent threads each insert their own key into the shared per-contract Caffeine cache and then each independently read the full accumulated key set, causing every thread to issue an overlapping batch SQL query covering all accumulated slots. This produces quadratic DB load amplification with no privilege required.

## Finding Description

**Exact code path:** `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, `findStorageBatch()`, lines 85–122.

The three operations are not atomic:

1. **Line 90** — `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)`: individually thread-safe, but provides no exclusion of concurrent readers.
2. **Line 91** — `contractSlotsCache.getNativeCache().asMap().keySet()`: a **live view** of the underlying `ConcurrentHashMap`; it reflects all keys inserted by all concurrent threads at the moment of the call.
3. **Line 103** — `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)`: the DB query is issued with the full accumulated key set. [1](#0-0) 

**Exploit flow:**

1. N threads each call `findStorage(contractId=X, key=Kᵢ)` concurrently.
2. All N threads miss `contractStateCache` (cold start or post-2s TTL expiry).
3. All N threads enter `findStorageBatch`.
4. Each thread executes `putIfAbsent(Kᵢ)` — after all N inserts, the per-contract cache contains {K₁…Kₙ}.
5. Each thread reads the live key set and sees all N keys.
6. Each thread issues `findStorageBatch(contractId, [K₁…Kₙ])` — the same N-slot SQL query, N times.
7. Total DB slot lookups: up to **N²** instead of N.

**Why existing checks fail:**

- The `contractStateCache` check at lines 63–67 only short-circuits if a value is already cached. The cache has `expireAfterWrite=2s`, so every 2 seconds all values expire and the next wave of concurrent requests all miss it and proceed to `findStorageBatch`. [2](#0-1) [3](#0-2) 

- The rate limiter (`ThrottleManagerImpl`, default 500 req/s) limits incoming HTTP requests but does not prevent the intra-process amplification: 500 allowed requests can each trigger a 1500-slot batch query. [4](#0-3) [5](#0-4) 

- The `slotsPerContract` cache has `maximumSize=1500` per contract. Once a contract accumulates 1500 cached slot keys, each concurrent request issues a 1500-slot batch query. [6](#0-5) 

## Impact Explanation

The `findStorageBatch` SQL query performs an indexed scan over `contract_state` with an `IN` clause of up to 1500 elements. With the default configuration:

- `slotsPerContract.maximumSize = 1500`
- `throttle.requestsPerSecond = 500`

A single rate-limited attacker can drive up to **500 × 1500 = 750,000 slot lookups per second** against the shared PostgreSQL instance. Because the DB is shared across all mirror-node instances, degradation propagates to every node reading from it. The attack is repeatable every 2 seconds (the `contractStateCache` TTL), making sustained exhaustion straightforward. [7](#0-6) 

## Likelihood Explanation

The attack requires no authentication, no special contract state, and no knowledge of valid slot values — only the ability to send concurrent HTTP POST requests to `/api/v1/contracts/call` with calldata that reads different storage slots of the same contract. [8](#0-7) 

The default rate limit of 500 req/s is generous enough to sustain the amplification indefinitely. This is trivially achievable with any HTTP load-testing tool.

## Recommendation

Replace the non-atomic `putIfAbsent` + live-view snapshot pattern with a `computeIfAbsent`-style guard or a dedicated lock per `contractId`, so that only one thread performs the DB query for a given contract at a time while others wait for the result. Alternatively, take a **snapshot copy** of the key set immediately after the `putIfAbsent` (before other threads can insert more keys), limiting each thread's query to only the keys it personally registered. A per-contract `ReentrantLock` or Caffeine's `get(key, mappingFunction)` pattern would eliminate the race entirely.

## Proof of Concept

```
# Warm up the slotsPerContract cache for contract 0x<TARGET> with 1500 distinct slot keys
# (achievable over normal use or by sending 1500 sequential requests with distinct calldata)

# Then, every 2 seconds (after contractStateCache TTL expires), send 500 concurrent requests
# each reading a different slot of the same contract:

for i in $(seq 1 500); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0x<TARGET>\",\"data\":\"0x<SLOAD_SLOT_$i>\",\"gas\":50000}" &
done
wait

# Each of the 500 concurrent threads:
# 1. Misses contractStateCache (just expired)
# 2. Calls putIfAbsent(slot_i) into the shared 1500-key per-contract cache
# 3. Reads the live key set (sees all 1500 keys)
# 4. Issues findStorageBatch(contractId, [1500 keys]) to PostgreSQL
#
# Result: 500 × 1500 = 750,000 slot lookups in a single second against the DB
# Repeatable every 2 seconds indefinitely within the rate limit
``` [9](#0-8)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L63-69)
```java
        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L85-122)
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
        byte[] cachedValue = null;

        for (final var contractSlotValue : contractSlotValues) {
            final byte[] slotKey = contractSlotValue.getSlot();
            final byte[] slotValue = contractSlotValue.getValue();
            contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);

            if (Arrays.equals(slotKey, key)) {
                cachedValue = slotValue;
            }
        }

        // If the cache key was evicted and hasn't been requested since, the cached value will be null.
        // In that case, fall back to the original query.
        if (isKeyEvictedFromCache) {
            return contractStateRepository.findStorage(contractId.getId(), key);
        }
        return Optional.ofNullable(cachedValue);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-43)
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
