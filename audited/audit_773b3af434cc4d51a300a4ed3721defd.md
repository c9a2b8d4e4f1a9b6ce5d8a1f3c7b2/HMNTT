### Title
Cache Griefing via Unbounded `expireAfterAccess` Refresh in `findStorageBatch()` Slot Key Cache

### Summary
An unprivileged external user can fill a target contract's per-contract slot key cache (`slotsPerContract`, `maximumSize=1500`) with up to 1500 attacker-controlled bogus slot keys, then keep every entry alive indefinitely by re-querying each key before the 5-minute `expireAfterAccess` window closes. Because `findStorageBatch()` unconditionally issues a batch DB query for every key currently in the per-contract cache, every subsequent legitimate query for that contract triggers a database lookup for up to 1500 rows instead of one, permanently degrading batch query performance for all legitimate callers.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.java`, `findStorageBatch()`, lines 85–122. [1](#0-0) 

**Cache configuration:**

- `contractSlotsCache` (`CACHE_MANAGER_CONTRACT_SLOTS`): `expireAfterAccess=5m, maximumSize=3000` — maps `contractId → CaffeineCache` (per-contract slot key cache).
- `slotsPerContract` (`CACHE_MANAGER_SLOTS_PER_CONTRACT`): `expireAfterAccess=5m, maximumSize=1500` — each per-contract cache holds up to 1500 slot keys, each with its own 5-minute access-based expiry.
- `contractStateCache` (`CACHE_MANAGER_CONTRACT_STATE`): `expireAfterWrite=2s` — slot values expire after 2 seconds, forcing frequent re-entry into `findStorageBatch()`. [2](#0-1) 

**Root cause and failed assumption:**

The design assumes that the per-contract slot key cache will organically contain only keys that legitimate users have previously queried. There is no validation that a queried slot key actually exists in the contract's storage before it is inserted into the per-contract cache via `putIfAbsent`: [3](#0-2) 

Any caller can insert arbitrary slot keys. The `expireAfterAccess=5m` policy on both the outer `contractSlotsCache` and the inner per-contract cache resets on every access. Iterating over `getNativeCache().asMap().keySet()` (line 91) does **not** reset per-entry access timers in Caffeine — only explicit `get`/`putIfAbsent` calls do. Therefore, the attacker must re-query each bogus key individually every <5 minutes, which is trivially achievable.

**Exploit flow:**

1. Attacker sends 1500 `eth_call`/`eth_getStorageAt` requests for contract X, each with a distinct, non-existent slot key. Each call reaches `findStorageBatch()`, inserts the bogus key via `putIfAbsent`, and fills the per-contract cache to its `maximumSize=1500` limit.
2. Because the per-contract cache is now full, any new legitimate slot key queried by a real user causes Caffeine to evict the least-recently-used entry (one of the legitimate keys, since the attacker refreshes their bogus keys more frequently).
3. Every 4 minutes, the attacker re-queries each of the 1500 bogus keys (≈6.25 req/s, well under the 500 req/s global throttle). Each re-query resets the `expireAfterAccess` timer for that slot key in the per-contract cache and for the contract's entry in the outer `contractSlotsCache`.
4. For every legitimate user query on contract X (after the 2-second `contractStateCache` expiry), `findStorageBatch()` reads all 1500 cached slot keys and issues a single batch DB query for all of them: [4](#0-3) 
5. The DB processes 1500 row lookups (all bogus, returning nothing) plus the legitimate key lookup. If the legitimate key was evicted by the attacker's keys, `isKeyEvictedFromCache` is `true` and the code falls back to a single-row query — but the 1500-row batch query was already issued and wasted. [5](#0-4) 

**Why existing checks are insufficient:**

- `maximumSize=1500` bounds the number of slot keys per contract but does not prevent the attacker from occupying all 1500 slots with bogus keys.
- `expireAfterAccess=5m` is intended to evict stale entries, but the attacker trivially resets it before expiry.
- The global rate limiter (500 req/s) is not a meaningful barrier: maintaining 1500 bogus keys requires only ≈6.25 req/s.
- There is no check that a queried slot key exists in the contract's on-chain storage before inserting it into the cache.
<cite repo="oyakh1/hiero-mirror-node--024" path="web3/src/main/java/org

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

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L118-120)
```java
        if (isKeyEvictedFromCache) {
            return contractStateRepository.findStorage(contractId.getId(), key);
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
