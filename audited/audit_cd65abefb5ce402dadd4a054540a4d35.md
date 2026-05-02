### Title
Cache Poisoning via Unbounded Non-Existent Slot Key Accumulation Leading to Oversized Batch DB Queries

### Summary
An unprivileged external user can pre-populate the per-contract `contractSlotsCache` with up to 1,500 non-existent slot keys for a single `contractId` by issuing repeated `findStorage` calls. Once poisoned, every subsequent legitimate `findStorage()` call for that contract that misses the short-lived (2-second) `contractStateCache` triggers a `findStorageBatch()` with up to 1,500 slots in the SQL `IN` clause, causing sustained and repeated DB overload for all users querying that contract.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70) checks `contractStateCache` first. On a miss, it calls `findStorageBatch()` (lines 85–122). [1](#0-0) 

Inside `findStorageBatch()`, line 90 unconditionally inserts the incoming key into the per-contract cache with `putIfAbsent`, regardless of whether the slot actually exists in the database: [2](#0-1) 

Line 91 then reads **all** keys currently in the per-contract cache, and line 103 issues a single batch DB query with all of them: [3](#0-2) 

The batch query in the repository uses an unbounded `IN (:slots)` clause: [4](#0-3) 

**Root cause:** `putIfAbsent` at line 90 adds any caller-supplied key to the per-contract cache with no validation that the slot exists. Non-existent slots are never written to `contractStateCache` (only found slots are cached there, lines 106–113), so they persist in the per-contract cache and are re-submitted in every subsequent batch query. [5](#0-4) 

**Cache size bounds:** The per-contract slots cache (`slotsPerContract`) has a default `maximumSize=1500`, not 3,000 as stated in the question (3,000 is the outer `contractSlots` cache that holds up to 3,000 *contracts*). The actual maximum IN-clause size is therefore **1,500 slots per contract**. [6](#0-5) 

The `contractStateCache` expires after only 2 seconds (`expireAfterWrite=2s`), meaning the oversized batch query is re-triggered on every request to the poisoned contract after each 2-second window. [7](#0-6) 

### Impact Explanation

Every legitimate `eth_call` or `eth_getStorageAt` request for any slot of the poisoned contract will issue a PostgreSQL query with up to 1,500 byte-array parameters in an `IN` clause against the `contract_state` table. This query runs repeatedly (every 2 seconds per active user) for the 5-minute lifetime of the per-contract cache. An attacker targeting a high-traffic contract (e.g., a popular ERC-20) can cause sustained DB CPU and I/O elevation, degrading response times for all users of the web3 API. The attacker can maintain the poisoned state indefinitely by periodically re-accessing the poisoned slots to reset the 5-minute `expireAfterAccess` timer.

### Likelihood Explanation

No privileges are required. The attack requires only HTTP access to the public `eth_call` or `eth_getStorageAt` endpoint. Filling the cache requires 1,500 requests; at the default `requestsPerSecond=500` global throttle, this takes approximately 3 seconds. The attack is trivially repeatable and automatable with a simple script. The attacker does not need to know any real slot keys — arbitrary 32-byte values suffice. [8](#0-7) 

### Recommendation

1. **Do not cache non-existent slots.** After `findStorageBatch()` returns, only add keys to the per-contract cache if they were found in the DB. Remove the unconditional `putIfAbsent` at line 90 and instead populate the per-contract cache only from `contractSlotValues` results.
2. **Alternatively, cap the batch size.** Before issuing the batch query, limit `cachedSlots` to a configurable maximum (e.g., 100) to bound the IN-clause size regardless of cache contents.
3. **Track negative results separately.** If negative caching is desired (to avoid re-querying missing slots), use a separate bounded negative-result cache with a short TTL, and exclude those keys from the batch query.

### Proof of Concept

```
# Step 1: Poison the per-contract cache for contract 0xTARGET
# Send 1500 eth_getStorageAt requests with distinct non-existent slot keys
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST http://mirror-node-web3:8545 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getStorageAt\",
         \"params\":[\"0xTARGET\",\"0x${SLOT}\",\"latest\"],\"id\":$i}" &
done
wait

# Step 2: Observe that any subsequent legitimate query for 0xTARGET
# now triggers a DB query with 1500 slots in the IN clause.
# Repeat step 1 every ~4 minutes to keep the cache poisoned indefinitely.

# Step 3 (optional amplification): Run step 1 against the top-N
# high-traffic contracts to degrade DB performance globally.
```

Every `findStorage()` call for `0xTARGET` after the 2-second `contractStateCache` TTL will execute:
```sql
SELECT slot, value FROM contract_state
WHERE contract_id = <TARGET_ID>
AND slot IN (<1500 byte-array parameters>)
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L86-103)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L106-114)
```java
        for (final var contractSlotValue : contractSlotValues) {
            final byte[] slotKey = contractSlotValue.getSlot();
            final byte[] slotValue = contractSlotValue.getValue();
            contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);

            if (Arrays.equals(slotKey, key)) {
                cachedValue = slotValue;
            }
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
