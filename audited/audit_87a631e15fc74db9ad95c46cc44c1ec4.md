### Title
Cache TTL Mismatch Enables Sustained DB Batch-Query Amplification via Slot Key Registry Inflation

### Summary
The `contractStateCache` expires after 2 seconds (`expireAfterWrite=2s`) while the per-contract slot key registry (`slotsPerContract`) persists for 5 minutes (`expireAfterAccess=5m`). Because `findStorage()` unconditionally calls `findStorageBatch()` on any `contractStateCache` miss, and `findStorageBatch()` always issues a DB query for every slot key currently registered in `slotsPerContract`, an unprivileged attacker can pre-populate the slot key registry with up to 1500 entries and then cause every subsequent request to any slot of that contract to trigger a 1500-slot batch DB query — repeated every 2 seconds for the full 5-minute registry lifetime.

### Finding Description

**Exact code locations:**

- `CacheProperties.java` lines 25, 28, 39: TTL definitions
  - `contractSlots`: `expireAfterAccess=5m,maximumSize=3000`
  - `contractState`: `expireAfterWrite=2s,maximumSize=25000`
  - `slotsPerContract`: `expireAfterAccess=5m,maximumSize=1500`

- `ContractStateServiceImpl.java` lines 58–70 (`findStorage`): any `contractStateCache` miss (null or `EMPTY_VALUE`) unconditionally falls through to `findStorageBatch()`.

- `ContractStateServiceImpl.java` lines 85–122 (`findStorageBatch`):
  - Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — registers the requested key into the per-contract slot registry.
  - Line 91: `contractSlotsCache.getNativeCache().asMap().keySet()` — collects **all** currently registered slot keys for this contract.
  - Line 103: `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — issues a single SQL `IN (...)` query for **all** collected keys.
  - Lines 94–101: `isKeyEvictedFromCache` is set to `false` whenever the requested key is found in the snapshot — which is always the case after `putIfAbsent` on line 90, so the fallback single-query path (line 119) is never taken under normal conditions.

**Root cause:** The design assumes that `contractStateCache` and `slotsPerContract` have comparable lifetimes, so that when a slot value expires the slot key also expires soon after. Instead, the 150× TTL ratio (2s vs 5m) means the key registry outlives the value cache by up to 300 refresh cycles. Each refresh cycle re-executes the full batch query for every key in the registry.

**Failed assumption:** The comment on line 89 reads *"Cached slot keys for contract, whose slot values are not present in the contractStateCache"* — implying the registry is a short-lived staging area. In practice it is a long-lived amplifier: keys accumulate for 5 minutes while values expire every 2 seconds.

### Impact Explanation

An attacker who registers N slot keys (max N = 1500 per contract, bounded by `slotsPerContract` `maximumSize`) causes every subsequent `findStorage()` call to that contract to execute a DB query scanning N rows instead of 1. The amplification factor is up to **1500×** per request. Because `contractStateCache` expires every 2 seconds, this amplified query fires up to **150 times per 5-minute window** per contract. With `contractSlotsCache` holding up to 3000 contract entries, an attacker targeting multiple contracts can multiply the effect further. The result is sustained, disproportionate PostgreSQL load (large `IN` clause scans on `contract_state`) that can degrade or deny service to all users of the web3 API without any privileged access.

### Likelihood Explanation

The attack requires no authentication. `eth_call` and `eth_getStorageAt` are standard public JSON-RPC endpoints. Accessing 1500 unique storage slots of a single contract is trivially achievable by calling a contract that iterates over a storage array, or by issuing 1500 `eth_getStorageAt` calls with different slot indices. The `enableBatchContractSlotCaching` flag defaults to `true` (CacheProperties line 30), so the vulnerable path is active in all default deployments. The attack is fully repeatable and requires no special on-chain state.

### Recommendation

1. **Align TTLs**: Set `contractSlots`/`slotsPerContract` TTL to be equal to or shorter than `contractState` TTL, so slot keys do not outlive their values.
2. **Cap batch size**: Before calling `findStorageBatch`, limit `cachedSlots` to a configurable maximum (e.g., 100) to bound the worst-case query size regardless of registry size.
3. **Evict slot keys on value expiry**: Use a Caffeine `removalListener` on `contractStateCache` to also evict the corresponding key from `slotsPerContract` when a value expires, keeping the two caches in sync.
4. **Rate-limit slot registration**: Track how many unique slot keys a single caller registers per contract per time window and reject or ignore excess registrations.

### Proof of Concept

**Preconditions:** Default configuration (`enableBatchContractSlotCaching=true`), public JSON-RPC endpoint accessible.

**Steps:**

1. Choose any deployed contract `C` with a known contract ID.
2. Send 1500 `eth_getStorageAt(C, slot_i)` requests with distinct slot indices `slot_0 … slot_1499`. Each call triggers `findStorage()` → `findStorageBatch()` → `putIfAbsent(slot_i)`, registering all 1500 keys in `slotsPerContract` for `C` (5-minute TTL, refreshed on each access).
3. Wait 3 seconds (> 2s `contractStateCache` TTL). All 1500 values are now expired from `contractStateCache`.
4. Send a single `eth_getStorageAt(C, slot_0)`. Observe in DB query logs that `findStorageBatch` issues `SELECT slot, value FROM contract_state WHERE contract_id = C AND slot IN (slot_0, slot_1, …, slot_1499)` — a 1500-row scan for a 1-slot request.
5. Repeat step 4 every 2 seconds. Each repetition re-triggers the 1500-slot batch query. Sustain for 5 minutes to exhaust the full registry window.
6. Confirm DB CPU/IO metrics show load proportional to 1500× the expected single-slot query cost.