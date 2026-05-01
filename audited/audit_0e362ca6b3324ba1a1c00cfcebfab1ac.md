### Title
Unsynchronized Two-Phase Cache Check Enables Cache Stampede / Thundering Herd DoS on DB

### Summary
`ContractStateServiceImpl.findStorage()` performs a non-atomic cache-miss check followed by an unconditional call to `findStorageBatch()`, with no mutex, no request coalescing, and no `sync=true` on the Caffeine cache. Any number of concurrent unauthenticated requests for the same uncached slot will all miss `contractStateCache` simultaneously, all enter `findStorageBatch()` concurrently, and each independently issue a batch DB query covering every tracked slot for that contract — up to 1,500 slots per query. This is a direct, repeatable DB amplification DoS requiring zero privileges.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` ( [1](#0-0) ) performs a plain, unsynchronized cache lookup at line 63:

```java
final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);
if (cachedValue != null && cachedValue != EMPTY_VALUE) {
    return Optional.of(cachedValue);
}
return findStorageBatch(contractId, key);
```

There is no `synchronized` block, no `CompletableFuture`-based coalescing, and no `sync=true` on the `CaffeineCacheManager`. The `contractStateCache` is configured with `expireAfterWrite=2s` ( [2](#0-1) ), meaning the entire cache flushes every 2 seconds, creating a predictable, repeatable stampede window.

Inside `findStorageBatch()` ( [3](#0-2) ):

- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` is atomic, but it only prevents duplicate key insertion — it does **not** prevent multiple threads from proceeding past it to the DB query.
- Line 91: `contractSlotsCache.getNativeCache().asMap().keySet()` — each concurrent thread reads the full set of tracked slot keys for the contract (up to `maximumSize=1500` per the `slotsPerContract` cache config). [4](#0-3) 
- Line 103: `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — each thread independently fires a `SELECT slot, value FROM contract_state WHERE contract_id = ? AND slot IN (...)` with up to 1,500 slot keys. [5](#0-4) 

**Root cause:** The check-then-act sequence (cache read → DB query) is not atomic. The `CaffeineCacheManager` is not configured with `sync=true`, so Spring's `@Cacheable` does not serialize concurrent loaders. The manual cache check in `findStorage()` has the same problem. There is no per-key or per-contract lock, semaphore, or request-coalescing mechanism anywhere in the path.

**Failed assumption:** The design assumes that once a slot is in `contractSlotsCache`, concurrent threads will not re-query the DB for it. But `contractStateCache` (the value cache) expires every 2 seconds, while `contractSlotsCache` (the key tracker) expires after 5 minutes. After each 2-second expiry of `contractStateCache`, all N concurrent threads will miss the value cache, all enter `findStorageBatch()`, and all issue full batch queries against the DB — even though the slot keys are still tracked.

### Impact Explanation

Each concurrent request issues a batch query for **all** tracked slots of the target contract (up to 1,500 slots). With N concurrent requests, the DB receives N × 1,500-slot queries simultaneously. The `db.statementTimeout` is 3,000 ms by default ( [6](#0-5) ), so queries do not fail fast. DB connection pool exhaustion follows, causing:

1. Web3 API request timeouts and failures for all users.
2. Shared DB resource contention with the importer process, which writes incoming transaction data from the Hedera network — slowing or stalling ingestion of new transactions.
3. The attack is self-reinforcing: as the DB slows, more requests pile up, each triggering more batch queries on the next 2-second cache expiry cycle.

### Likelihood Explanation

**Preconditions:** None. The web3 API (`eth_getStorageAt`, `eth_call`) is publicly accessible with no authentication. The attacker needs only a valid contract address and any slot key.

**Trigger:** Send N concurrent HTTP requests (e.g., via `curl`, `ab`, or any HTTP load tool) for the same `contractId`/`key` pair, timed to arrive within the same 2-second `contractStateCache` expiry window. This is trivially repeatable every 2 seconds.

**Amplification:** If the attacker first "warms" the `contractSlotsCache` by querying 1,500 distinct slots for a contract (within the 5-minute `slotsPerContract` TTL), then triggers the stampede, each of the N concurrent requests issues a 1,500-slot batch query. The amplification factor is N × 1,500.

**No special knowledge required:** Contract addresses and slot keys for popular contracts are publicly known from on-chain data.

### Recommendation

1. **Enable Caffeine's built-in request coalescing** for `contractStateCache` by setting `sync=true` on the `@Cacheable` annotation on `ContractStateRepository.findStorage()`, or by configuring the `CaffeineCacheManager` with `.build(key -> ...)` loader semantics. This ensures only one thread loads a given key while others wait.

2. **Add a per-key lock or `ConcurrentHashMap`-based in-flight tracker** in `ContractStateServiceImpl.findStorage()` so that concurrent requests for the same `(contractId, key)` pair are coalesced: the first thread issues the DB query, and subsequent threads wait for and reuse its result.

3. **Reduce the blast radius** by capping the number of slots included in a single `findStorageBatch()` call, independent of how many keys are in `contractSlotsCache`.

4. **Add rate limiting** at the web3 API layer (per IP or per contract) to bound the number of concurrent storage queries.

### Proof of Concept

```bash
# 1. Warm the slotsPerContract cache: query 1500 distinct slots for contract 0.0.1234
for i in $(seq 1 1500); do
  curl -s -X POST http://mirror-node:8545 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_getStorageAt\",\"params\":[\"0x<contract_addr>\",\"0x$(printf '%064x' $i)\",\"latest\"],\"id\":$i}" &
done
wait

# 2. Wait for contractStateCache to expire (2 seconds)
sleep 3

# 3. Trigger stampede: N concurrent requests for the same slot
for i in $(seq 1 200); do
  curl -s -X POST http://mirror-node:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_getStorageAt","params":["0x<contract_addr>","0x0000000000000000000000000000000000000000000000000000000000000001","latest"],"id":1}' &
done
wait

# Result: 200 concurrent findStorageBatch() calls each querying 1500 slots = 300,000 slot lookups
# hitting the DB simultaneously, exhausting the connection pool.
# Repeat every 2 seconds to sustain the DoS.
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-28)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
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

**File:** docs/configuration.md (L702-702)
```markdown
| `hiero.mirror.web3.db.statementTimeout`                      | 3000                                               | The number of milliseconds to wait before timing out a query statement                                                                                                                           |
```
