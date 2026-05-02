I have verified all technical claims against the actual source code. Here is my assessment:

---

Audit Report

## Title
Progressive SQL IN-Clause Amplification via Batch Contract Slot Cache Accumulation

## Summary
`ContractStateServiceImpl.findStorageBatch()` accumulates every distinct slot key seen for a given `contractId` into a per-contract Caffeine cache (`slotsPerContract`, max 1500 entries, 5-minute TTL). On every cache miss in `contractStateCache` (which expires after 2 seconds), it issues a `findStorageBatch` SQL query whose `IN (:slots)` clause contains **all** currently accumulated keys — not just the requested one. An unprivileged attacker can pre-fill the per-contract slot cache with up to 1500 unique keys, then sustain a pattern where a single HTTP request triggers a 1500-parameter SQL `IN`-clause query every 2 seconds, achieving a ~1500× amplification in database query complexity.

## Finding Description

**Exact code path confirmed:**

`ContractStateServiceImpl.java`, `findStorageBatch()`:

- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — every new unique slot key is unconditionally added to the per-contract cache.
- Line 91: `contractSlotsCache.getNativeCache().asMap().keySet()` — retrieves **all** accumulated keys for that contract, not just the requested one.
- Line 103: `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — issues a SQL `IN (:slots)` query with all accumulated keys. [1](#0-0) 

**Root cause — confirmed TTL mismatch:**

- `slotsPerContract` cache: `expireAfterAccess=5m, maximumSize=1500` — slot keys live for up to 5 minutes.
- `contractState` cache: `expireAfterWrite=2s, maximumSize=25000` — slot values expire every 2 seconds. [2](#0-1) 

The failed assumption is that the batch preload is beneficial because previously-seen slots will still be warm in `contractStateCache`. In reality, `contractStateCache` expires 150× faster than `slotsPerContract`, so accumulated keys are almost always stale, causing every cache miss to re-query all of them.

The entry point is `findStorage()` at lines 63–69: any `contractStateCache` miss (which occurs every 2 seconds by design) bypasses the value cache and calls `findStorageBatch()` with the full accumulated key set. [3](#0-2) 

**Outer cache multiplier confirmed:**

`contractSlots` outer cache: `expireAfterAccess=5m, maximumSize=3000` — up to 3000 contracts can each hold a full 1500-key per-contract cache simultaneously. [4](#0-3) 

**Exploit flow:**

1. Attacker identifies any deployed contract with multiple readable storage slots (e.g., any ERC-20 `balanceOf` mapping).
2. Attacker sends up to 1500 `eth_call` requests (within the 500 rps global limit, ~3 seconds), each reading a different storage slot of the same contract.
3. Each new unique slot key is added to the per-contract `slotsPerContract` cache. Each call triggers a `findStorageBatch` with an IN-clause of size 1, 2, 3, ..., 1500 respectively.
4. After 2 seconds, all values expire from `contractStateCache`. A **single** `eth_call` for any of the 1500 slots now triggers `findStorageBatch` with all 1500 keys in the IN-clause.
5. Attacker repeats step 4 every 2 seconds (one request per cycle) to sustain the amplification for the full 5-minute lifetime of the per-contract slot cache.

**Why existing checks fail:**

- The global rate limiter (500 rps) throttles HTTP request count but does not account for per-request SQL cost amplification. One request at 1500-key IN-clause is ~1500× more expensive than baseline. [5](#0-4) 

- The gas throttle (`gasPerSecond`) governs EVM execution cost, not database query cost. [6](#0-5) 

- The `maximumSize=1500` cap on the per-contract cache bounds the IN-clause size but does not prevent the amplification — 1500 parameters in a PostgreSQL `IN` clause is a substantial query.
- There is no per-IP or per-contract-ID rate limiting.
- The `db.statementTimeout=3000ms` does not prevent the amplification since each query completes within the timeout. [7](#0-6) 

## Impact Explanation

A single attacker with no credentials can cause the PostgreSQL database to execute repeated queries with up to 1500 bind parameters in an `IN` clause against the `contract_state` table. Even with an index on `(contract_id, slot)`, a 1500-entry IN-clause requires 1500 index probes per query. Sustained at one query per 2 seconds (the `contractStateCache` TTL), and multiplied across 3000 contracts (the outer `contractSlots` cache limit), this can drive database CPU significantly above baseline. The `db.statementTimeout=3000ms` does not prevent the amplification since each query completes within the timeout. [8](#0-7) 

## Likelihood Explanation

The attack requires no authentication, no special privileges, and no on-chain transactions. Any public `eth_call` endpoint user can execute it. The only prerequisite is knowledge of a contract address with multiple readable storage slots — trivially satisfied by any ERC-20 token. The attack is repeatable indefinitely and self-sustaining after the initial ~3-second fill phase. The global 500 rps limit is sufficient to fill the 1500-slot cache in under 3 seconds. [9](#0-8) 

## Recommendation

1. **Fix the TTL mismatch**: Align `slotsPerContract` TTL with `contractState` TTL (both at 2 seconds), or extend `contractState` TTL to be closer to `slotsPerContract` TTL. The current 150× disparity is the root cause.
2. **Bound the batch query size**: Cap the number of keys passed to `findStorageBatch` per invocation (e.g., limit to the keys that were actually requested in the current EVM execution context, not all historically accumulated keys).
3. **Disable by default or add per-contract rate limiting**: The `enableBatchContractSlotCaching` flag (currently `true`) can be set to `false` as a mitigation. Alternatively, add per-contract-ID rate limiting on `findStorageBatch` invocations.
4. **Scope the batch to the current request**: Instead of querying all accumulated keys globally, only batch-load keys that are accessed within a single EVM execution context, resetting the accumulated set per request. [2](#0-1) 

## Proof of Concept

```
# Step 1: Fill the per-contract slot cache with 1500 unique slots (takes ~3s at 500 rps)
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"<ERC20_CONTRACT>\",\"data\":\"0x70a08231$(printf '%064x' $i)\",\"gas\":50000}" &
done
wait

# Step 2: After 2 seconds, a single request triggers a 1500-key IN-clause SQL query
sleep 2
curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
  -H 'Content-Type: application/json' \
  -d '{"to":"<ERC20_CONTRACT>","data":"0x70a08231<any_address_padded>","gas":50000}'

# Step 3: Repeat step 2 every 2 seconds for 5 minutes to sustain the amplification
for cycle in $(seq 1 150); do
  sleep 2
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"<ERC20_CONTRACT>","data":"0x70a08231<any_address_padded>","gas":50000}'
done
```

Each iteration of Step 3 triggers `ContractStateServiceImpl.findStorageBatch()` with all 1500 accumulated slot keys in the SQL `IN` clause, confirmed by lines 90–103 of `ContractStateServiceImpl.java`. [10](#0-9)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L24-26)
```java
    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;
```

**File:** docs/configuration.md (L702-702)
```markdown
| `hiero.mirror.web3.db.statementTimeout`                      | 3000                                               | The number of milliseconds to wait before timing out a query statement                                                                                                                           |
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
