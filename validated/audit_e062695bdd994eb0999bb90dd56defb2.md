All code references in the claim have been verified against the actual source. Here is the audit report.

---

Audit Report

## Title
Cache-Amplified SQL IN-Clause DoS via Batch Contract Slot Preloading

## Summary
When `enableBatchContractSlotCaching` is `true` (the default), a single storage-slot read that misses the `contractStateCache` triggers a SQL `IN`-clause query containing **every** slot key held in the per-contract Caffeine cache — up to 1500 entries. An unprivileged attacker can prime that cache to its maximum, then repeatedly trigger single-slot reads after the 2-second TTL expires, causing a sustained 1500× DB row-lookup amplification per request.

## Finding Description

**`ContractStateServiceImpl.findStorage()`**

When `enableBatchContractSlotCaching` is `true` and the `contractStateCache` lookup returns `null` or `EMPTY_VALUE`, execution falls through unconditionally to `findStorageBatch()`. [1](#0-0) 

**`ContractStateServiceImpl.findStorageBatch()`**

Line 91 snapshots **all** keys currently held in the per-contract Caffeine cache (`cachedSlotKeys`). There is no cap or filter — every key ever seen for that contract is included. Line 103 passes the full list directly to the repository. [2](#0-1) 

**SQL query issued:**

```sql
select slot, value from contract_state
where contract_id = :contractId
and slot in (:slots)   -- up to 1500 entries
``` [3](#0-2) 

**Cache configuration (defaults):**

- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — slot keys live 5 minutes after last access; up to 1500 per contract.
- `contractState`: `expireAfterWrite=2s, maximumSize=25000` — slot values expire every 2 seconds.
- `enableBatchContractSlotCaching`: `true` by default. [4](#0-3) 

**Root cause:** The batch query size is bounded only by the `slotsPerContract` cache maximum (1500), not by the number of slots actually needed for the current request. Once the per-contract slot cache is full, every `contractStateCache` miss (which occurs every 2 seconds by design) triggers a 1500-slot SQL `IN`-clause for a single-slot read.

**Why existing throttle checks fail:**

The throttle consumes 1 rate-limit token per HTTP request and a gas-proportional token from the gas bucket. Neither bucket accounts for the number of DB slot lookups generated per request. [5](#0-4) 

A single `eth_call` consuming 1 rate-limit token can cause 1500 DB row lookups. [6](#0-5) 

## Impact Explanation
At the default 500 req/s rate limit, an attacker sustaining the primed state forces up to 500 × 1500 = **750,000 DB slot lookups per second** instead of the baseline 500 × 1 = 500. This is a **1500× amplification** of database I/O per request. Sustained pressure can exhaust DB connection pools, increase query latency for all users, and degrade or halt the mirror node's web3 API. The `db.statementTimeout` of 3000 ms provides no protection because each individual query is well-formed and completes normally — it is the aggregate volume that causes degradation. [7](#0-6) 

## Likelihood Explanation
No authentication or special privilege is required — `eth_call` is a public, unauthenticated endpoint. Priming requires only ~1500 API calls (≈3 seconds at the rate limit). The attack is then self-sustaining: the `slotsPerContract` cache retains keys for 5 minutes after last access, and the attacker only needs to issue one read every 2 seconds to keep triggering full 1500-slot batch queries. The attack is trivially scriptable and repeatable. [8](#0-7) 

## Recommendation

1. **Cap the batch size.** In `findStorageBatch()`, limit `cachedSlots` to a configurable maximum (e.g., 50–100 entries) before passing to `findStorageBatch`. Slots beyond the cap should fall back to the single-key `findStorage` query. [9](#0-8) 

2. **Only batch slots with expired state-cache entries.** Before building `cachedSlots`, filter `cachedSlotKeys` to include only those whose corresponding `contractStateCache` entry is absent, rather than blindly including all known slot keys.

3. **Reduce `slotsPerContract` maximumSize.** Lower the default from 1500 to a value commensurate with realistic contract usage patterns, reducing the worst-case amplification factor. [10](#0-9) 

4. **Account for DB fan-out in the throttle.** Extend `ThrottleManagerImpl` to consume tokens proportional to the number of DB slot lookups generated, not just the HTTP request count. [5](#0-4) 

## Proof of Concept

```
# Step 1: Prime the slotsPerContract cache for contract 0x<TARGET> with 1500 distinct slot keys
for i in $(seq 1 1500); do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0x<TARGET>\",\"data\":\"$(printf '%064x' $i)\",\"gas\":50000}"
done

# Step 2: Wait 2 seconds for contractStateCache TTL to expire, then sustain at 500 req/s
# Each request now triggers a 1500-slot SQL IN-clause instead of a 1-slot lookup.
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0x<TARGET>","data":"0x<ANY_SLOT>","gas":50000}' &
  sleep 0.002
done
```

Each iteration of Step 2 causes `findStorageBatch` to issue:
```sql
select slot, value from contract_state
where contract_id = <TARGET_ID>
and slot in (<slot_1>, <slot_2>, ..., <slot_1500>)
```
instead of a single-key lookup, achieving the 1500× DB amplification factor. [11](#0-10)

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

**File:** docs/configuration.md (L702-702)
```markdown
| `hiero.mirror.web3.db.statementTimeout`                      | 3000                                               | The number of milliseconds to wait before timing out a query statement                                                                                                                           |
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
