### Title
Cache-Amplified Database Query Inflation via Unbounded Slot Key Accumulation in `findStorageBatch()`

### Summary
`ContractStateServiceImpl.findStorageBatch()` unconditionally issues a DB `IN`-clause query containing every slot key ever accumulated in the per-contract Caffeine cache, not just the one key being requested. An unprivileged caller can pre-seed this cache with up to 1,500 distinct slot keys (the actual `slotsPerContract` maximum) by making 1,500 ordinary `eth_call` requests. After seeding, every single subsequent `findStorage()` call for that contract — including calls for non-existent slots — triggers a 1,500-entry `IN`-clause query against the `contract_state` table, sustained indefinitely because non-existent slot keys are never written to the short-lived `contractStateCache`.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70) checks `contractStateCache` first. On a miss it delegates to `findStorageBatch()` (lines 85–122). [1](#0-0) 

Inside `findStorageBatch()`:
- Line 90 unconditionally inserts the incoming key into the per-contract `contractSlotsCache` with sentinel `EMPTY_VALUE`.
- Line 91 snapshots **the entire key-set** of that cache.
- Line 103 passes the full key-set to `contractStateRepository.findStorageBatch()`. [2](#0-1) 

The repository executes a raw `slot IN (:slots)` query with no server-side size guard: [3](#0-2) 

**Root cause — failed assumption:** The design assumes that only "previously seen, real" slot keys accumulate in the per-contract cache, so querying all of them is cheap. There is no validation that a requested slot key actually exists in the contract before it is inserted into the cache.

**Why non-existent keys create a persistent amplification (worse than the 2-second expiry path):**

`contractStateCache.put()` is called only for keys that the DB returns a value for (line 109). Non-existent slot keys are never written to `contractStateCache`. [4](#0-3) 

Therefore, for a non-existent slot key:
1. `contractStateCache.get(...)` always returns `null` → `findStorageBatch()` is always called.
2. The key is already in `contractSlotsCache` → the full 1,500-key batch is always issued.
3. No cache expiry is needed; the amplification is permanent for the 5-minute `expireAfterAccess` lifetime of the per-contract cache. [5](#0-4) 

**Cache size bounds:**

- `slotsPerContract` (per-contract slot key cache): `maximumSize=1500` — this is the actual ceiling for the IN-clause, not 3,000.
- `contractSlots` (outer cache, maps `contractId → per-contract CaffeineCache`): `maximumSize=3000` — this is the number of contracts, not slot keys per contract. [6](#0-5) 

**Throttle is insufficient:** The `ThrottleManagerImpl` enforces an HTTP-level rate limit (default 500 req/s) and a gas-per-second budget. Neither limits the number of DB rows scanned per request. [7](#0-6) 

### Impact Explanation

After the one-time seeding phase, every `eth_call` or `eth_estimateGas` request that touches any slot of the poisoned contract causes the database to evaluate a `WHERE slot IN (1500 entries)` predicate against the `contract_state` table. At the default 500 req/s rate limit, this translates to up to 750,000 slot comparisons per second from a single attacker, compared to 500 for a clean workload — a 1,500× amplification of DB I/O per request. Sustained over minutes (the `expireAfterAccess=5m` window), this can saturate DB CPU and I/O, degrading or denying service to legitimate users. The `db.statementTimeout=3000ms` provides a partial backstop but does not prevent the amplification from accumulating across concurrent requests. [8](#0-7) 

### Likelihood Explanation

The attack requires no credentials, no on-chain funds, and no special tooling — only the ability to call `POST /api/v1/contracts/call`, which is the standard public JSON-RPC endpoint. The seeding phase (1,500 calls) completes in under 3 seconds at the default rate limit. The attacker can target any high-traffic contract to maximize collateral impact. The attack is fully repeatable: after the 5-minute `expireAfterAccess` window expires, re-seeding takes another 3 seconds. The non-existent-key variant requires no timing coordination and no waiting for `contractStateCache` expiry. [9](#0-8) 

### Recommendation

1. **Cap the IN-clause at query time:** Before calling `contractStateRepository.findStorageBatch()`, truncate `cachedSlots` to a configurable maximum (e.g., 100–200 entries). Keys beyond the cap fall back to the single-key `findStorage()` path.
2. **Do not insert keys into `contractSlotsCache` before confirming existence:** Only add a slot key to the per-contract cache after the DB confirms it has a value, or after a single-key lookup succeeds.
3. **Negative-cache non-existent keys in `contractStateCache`:** Store a sentinel (e.g., `EMPTY_VALUE`) in `contractStateCache` for slots confirmed absent, so repeated lookups for non-existent keys short-circuit before reaching `findStorageBatch()`.
4. **Add per-contract slot-key insertion rate limiting** to prevent rapid cache inflation from a single caller.

### Proof of Concept

**Preconditions:** Mirror node web3 module running with default config; any deployed contract address `CONTRACT_ADDR`.

**Step 1 — Seed phase (≈1,500 `eth_call` requests, ~3 seconds):**
```
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)   # unique non-existent slot key
  curl -s -X POST http://mirror-node:8545/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"$CONTRACT_ADDR\",\"data\":\"0x$(python3 -c "print('20965255' + '$SLOT')")\",\"gas\":100000}"
done
```
Each call triggers `findStorageBatch()`, inserting a new non-existent slot key into the per-contract `contractSlotsCache`.

**Step 2 — Sustained amplification (single request, repeatable indefinitely):**
```
curl -X POST http://mirror-node:8545/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"CONTRACT_ADDR","data":"0x<any-slot-read>","gas":100000}'
```
Each call now issues `SELECT slot, value FROM contract_state WHERE contract_id = ? AND slot IN (<1500 entries>)` against the DB, regardless of whether the requested slot exists.

**Step 3 — Observe:** Monitor DB `pg_stat_activity` or slow-query logs; each request generates a 1,500-entry IN-clause scan. At 500 req/s the DB processes 750,000 slot comparisons/second from this single attacker, sustained for 5 minutes per seeding cycle. [10](#0-9)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L24-39)
```java
    @NotBlank
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
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
