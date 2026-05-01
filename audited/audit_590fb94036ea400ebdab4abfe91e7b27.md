### Title
Missing Negative Cache for Non-Existent Storage Slots Enables Repeated DB Query Amplification

### Summary
`ContractStateServiceImpl.findStorageBatch()` places a non-existent slot key into `contractSlotsCache` with `EMPTY_VALUE` as a placeholder, but never writes anything to `contractStateCache` when the DB returns no row for that slot. Because `findStorage()` only checks `contractStateCache` for the short-circuit, every subsequent call for the same non-existent slot bypasses the cache and issues a fresh batch DB query, with no bound on repetition for the lifetime of the `contractSlotsCache` entry (up to 5 minutes by default).

### Finding Description

**Exact code path:**

`findStorage()` at line 63 reads from `contractStateCache`:

```java
final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);
if (cachedValue != null && cachedValue != EMPTY_VALUE) {
    return Optional.of(cachedValue);
}
return findStorageBatch(contractId, key);   // always reached for non-existent slots
``` [1](#0-0) 

`findStorageBatch()` at line 90 puts the key into `contractSlotsCache` with `EMPTY_VALUE`:

```java
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
``` [2](#0-1) 

The DB query at line 103 runs against all accumulated slot keys:

```java
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
``` [3](#0-2) 

The write to `contractStateCache` at line 109 only executes inside the loop over returned rows:

```java
for (final var contractSlotValue : contractSlotValues) {
    contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);
``` [4](#0-3) 

**Root cause:** When the DB returns zero rows for a slot (slot does not exist), the loop body never executes, so `contractStateCache` is never populated for that key. On the next call, `contractStateCache.get()` returns `null` again, the short-circuit at line 65 is not taken, and `findStorageBatch()` is called again — issuing another DB query. This repeats indefinitely while the key lives in `contractSlotsCache` (default TTL: `expireAfterAccess=5m`, max 1500 entries per contract). [5](#0-4) 

The fallback path at line 118–119 (which uses the `@Cacheable`-annotated `findStorage()` and would cache the empty result) is only reached when `isKeyEvictedFromCache == true`, i.e., the key was evicted from `contractSlotsCache`. As long as the key remains in `contractSlotsCache`, the eviction branch is never taken. [6](#0-5) 

The repository's `findStorageBatch` has no `@Cacheable` annotation, confirming results are never automatically cached: [7](#0-6) 

### Impact Explanation

Every `eth_call` or `estimateGas` request that triggers an SLOAD on a non-existent storage slot causes at least one `findStorageBatch` DB query. A contract with N SLOADs on non-existent slots causes N batch queries per request, and each batch query grows to include all previously seen slot keys for that contract. With the default gas throttle of 1.5 billion gas/second and a cold SLOAD costing 2100 gas, an attacker can sustain ~714,000 SLOAD operations per second, each generating a DB round-trip. This can saturate the PostgreSQL connection pool and degrade or deny service to all mirror node users. The `requestsPerSecond` limit of 500 does not prevent this because a single request can contain thousands of SLOADs. [8](#0-7) [9](#0-8) 

### Likelihood Explanation

No authentication or special privilege is required. Any user who can POST to `/api/v1/contracts/call` can trigger this. The attacker only needs to call a contract (or deploy a trivial one) that reads from storage slots that have never been written. This is trivially achievable: any freshly deployed contract has all slots at zero/uninitialized, and reading them via `eth_call` repeatedly is a standard, unauthenticated operation. The attack is repeatable and stateless from the attacker's perspective. [10](#0-9) 

### Recommendation

Implement negative caching for non-existent slots. After `findStorageBatch()` completes and a requested slot key is not present in the returned results, explicitly write a sentinel value (e.g., `EMPTY_VALUE`) into `contractStateCache` for that key:

```java
// After the loop over contractSlotValues:
if (cachedValue == null && !isKeyEvictedFromCache) {
    // Slot does not exist in DB — cache the negative result
    contractStateCache.put(generateCacheKey(contractId, key), EMPTY_VALUE);
}
```

Then update the short-circuit in `findStorage()` to treat `EMPTY_VALUE` in `contractStateCache` as a confirmed "not found" result and return `Optional.empty()` immediately, rather than falling through to `findStorageBatch()` again:

```java
if (cachedValue != null) {
    return cachedValue == EMPTY_VALUE ? Optional.empty() : Optional.of(cachedValue);
}
``` [1](#0-0) 

### Proof of Concept

**Preconditions:**
- Mirror node web3 module running with `enableBatchContractSlotCaching=true` (default).
- Any deployed contract whose storage slots have never been written (all slots are uninitialized).

**Steps:**

1. Deploy a contract `C` at address `0xABCD...` on the network. All its storage slots are uninitialized (no rows in `contract_state` for this contract).

2. Craft an `eth_call` payload that calls a function on `C` which executes 100 SLOAD opcodes on distinct uninitialized slots (e.g., `slot[0]` through `slot[99]`).

3. Send the request repeatedly:
   ```bash
   for i in $(seq 1 1000); do
     curl -s -X POST http://mirror-node:8545/api/v1/contracts/call \
       -H 'Content-Type: application/json' \
       -d '{"to":"0xABCD...","data":"<calldata for 100 SLOADs>","gas":15000000}'
   done
   ```

4. **Observe:** Each iteration triggers 100+ `findStorageBatch` DB queries (one per SLOAD, growing as the slot key set accumulates). The DB query count scales linearly with the number of requests. After 1000 requests, the DB has received 100,000+ batch queries for slots that will never exist, with no caching benefit between requests.

5. **Verify:** Monitor PostgreSQL `pg_stat_activity` or mirror node metrics to confirm the query rate scales with request rate, and that no caching occurs for the non-existent slots across requests.

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

**File:** docs/configuration.md (L691-691)
```markdown
| `hiero.mirror.web3.cache.slotsPerContract`                   | expireAfterAccess=5m,maximumSize=1500              | Cache for slot keys per contract. Separate instance used for the value of each entry of the contractSlots cache                                                                                  |
```

**File:** docs/configuration.md (L719-727)
```markdown
| `hiero.mirror.web3.throttle.gasPerSecond`                    | 1500000000                                         | Maximum gas limit that can be processed per second. The max value for this property is 1000000000. In case greater gas limit needs to be allowed per second, please refer to the property below. |
| `hiero.mirror.web3.throttle.opcodeRequestsPerSecond`         | 1                                                  | Maximum RPS limit for `/contracts/results/{transactionIdOrHash}/opcodes` endpoint. Note that this endpoint is heavy and the value needs to be low.                                               |
| `hiero.mirror.web3.throttle.request[].action`                | LOG                                                | The action to take if the request filter matches. One of `LOG`, `REJECT`, or `THROTTLE`.                                                                                                         |
| `hiero.mirror.web3.throttle.request[].filters[].expression`  |                                                    | The expression or field value to filter the request field                                                                                                                                        |
| `hiero.mirror.web3.throttle.request[].filters[].field`       | DATA                                               | The field to target for filtering requests                                                                                                                                                       |
| `hiero.mirror.web3.throttle.request[].filters[].type`        | CONTAINS                                           | How the field should be matched against the request field                                                                                                                                        |
| `hiero.mirror.web3.throttle.request[].limit`                 | Long.MAX_VALUE                                     | The maximum amount of requests that the action should be applied to requests that match.                                                                                                         |
| `hiero.mirror.web3.throttle.request[].rate`                  | 100                                                | The rate at which the action should apply to matched requests.                                                                                                                                   |
| `hiero.mirror.web3.throttle.requestsPerSecond`               | 500                                                | Maximum RPS limit                                                                                                                                                                                |
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
