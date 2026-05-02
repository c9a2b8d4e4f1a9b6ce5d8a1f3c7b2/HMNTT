### Title
Cache TTL Asymmetry Enables Persistent DB Batch Query Amplification via Slot Key Accumulation

### Summary
The `findStorageBatch()` method in `ContractStateServiceImpl` accumulates slot keys in the `slotsPerContract` cache (TTL: `expireAfterAccess=5m`) and uses the full accumulated key set as the IN-clause of every batch DB query. Because `contractStateCache` expires after only 2 seconds, an attacker who pre-fills `slotsPerContract` with up to 1500 keys can force every subsequent `findStorage` call to issue a DB query with 1500 slots — a 1500× amplification — sustained indefinitely with minimal request rate.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70) checks `contractStateCache` first. On a miss, it delegates to `findStorageBatch()` (lines 85–122).

Inside `findStorageBatch()`: [1](#0-0) 

- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — unconditionally registers the requested key into the per-contract `slotsPerContract` cache.
- Line 91: `cachedSlotKeys` = **all** keys ever registered for this contract.
- Line 103: `findStorageBatch(contractId.getId(), cachedSlots)` — issues one SQL `IN (:slots)` query with every accumulated key.

**Cache configurations:** [2](#0-1) 

- `contractStateCache`: `expireAfterWrite=2s, maximumSize=25000` — values expire 2 seconds after write.
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — keys survive 5 minutes per access.
- `contractSlotsCache` (outer): `expireAfterAccess=5m, maximumSize=3000`.

**Root cause and failed assumption:**

The design assumes the batch query fires once on a cold cache and then the warm `contractStateCache` absorbs subsequent requests for 2 seconds. The failed assumption is that the attacker cannot keep `contractStateCache` perpetually cold while keeping `slotsPerContract` perpetually full.

**Why existing checks fail:**

The `isKeyEvictedFromCache` guard (lines 94–100) only falls back to a single-slot query when the requested key was evicted from `slotsPerContract`. Since the attacker accesses the contract every 2 seconds, `expireAfterAccess=5m` is never triggered, so `isKeyEvictedFromCache` is always `false` and the full batch query always executes. [3](#0-2) 

**Exploit flow using non-existent slot keys (worst case):**

1. Attacker sends 1500 `eth_call` requests for contract C, each with a distinct random 32-byte slot key that does not exist in the DB.
2. Each call: key is added to `slotsPerContract[C]`; `findStorageBatch` runs; DB returns empty; `contractStateCache` is **never populated** for these keys.
3. After phase 1, `slotsPerContract[C]` holds 1500 keys. `contractStateCache` holds nothing for them.
4. Every subsequent `findStorage` call for contract C (even for a real slot) misses `contractStateCache` → calls `findStorageBatch` → issues `SELECT … WHERE slot IN (1500 keys)`.
5. Attacker sends 1 request every 2 seconds per contract to sustain the amplification. The `expireAfterAccess` timer resets on each access, keeping all 1500 keys alive.
6. Scale to 3000 contracts (outer `contractSlotsCache` limit): 3000 contracts × 1500 slots × 30 queries/min = **135,000,000 slot lookups/min** from 90,000 attacker requests/min.

### Impact Explanation

Each attacker request triggers a DB query with up to 1500 rows in the IN-clause instead of 1. This is a **1500× DB read amplification** per contract. At the maximum cache fill (3000 contracts), the ratio of attacker-induced DB work to attacker request volume is ~1500:1. PostgreSQL must evaluate the IN-clause, perform index scans, and return results for all 1500 slots on every query. This directly increases CPU, I/O, and connection pool pressure on the database, easily exceeding the 30% resource consumption threshold with a modest request rate. No privileged access, authentication, or on-chain funds are required.

### Likelihood Explanation

The attack requires only:
- Knowledge of any valid contract ID (publicly enumerable via the mirror node REST API).
- The ability to send unauthenticated JSON-RPC `eth_call` requests (standard public endpoint).
- No real slot keys needed — random 32-byte values suffice.

The attack is fully repeatable, requires no special tooling beyond a script sending HTTP requests, and is sustainable indefinitely. The 2-second `contractStateCache` TTL means the amplification window resets automatically every 2 seconds without any attacker action beyond keeping the `slotsPerContract` cache alive with periodic accesses.

### Recommendation

1. **Align TTLs**: Set `contractStateCache` TTL ≥ `slotsPerContract` TTL, or set `slotsPerContract` TTL ≤ `contractStateCache` TTL. The current 150:1 ratio (5m vs 2s) is the root cause.
2. **Bound batch size independently of accumulated history**: Cap the IN-clause to a configurable maximum (e.g., 50 slots) regardless of how many keys are in `slotsPerContract`.
3. **Evict slot keys when their values expire**: When a `contractStateCache` entry expires, remove the corresponding key from `slotsPerContract` so stale keys do not accumulate.
4. **Rate-limit or validate slot key registration**: Do not register a slot key in `slotsPerContract` unless it is confirmed to exist in the DB, preventing phantom key accumulation.

### Proof of Concept

```python
import requests, os, json, time

RPC = "http://<mirror-node>:8545"
CONTRACT = "0x<any_valid_contract_address>"

# Phase 1: Fill slotsPerContract with 1500 non-existent slot keys
for i in range(1500):
    slot = hex(i).zfill(66)  # random 32-byte slot key
    payload = {
        "jsonrpc": "2.0", "method": "eth_getStorageAt",
        "params": [CONTRACT, slot, "latest"], "id": i
    }
    requests.post(RPC, json=payload)

print("slotsPerContract filled with 1500 keys")

# Phase 2: Every 2 seconds, 1 request triggers a 1500-slot batch DB query
while True:
    payload = {
        "jsonrpc": "2.0", "method": "eth_getStorageAt",
        "params": [CONTRACT, "0x0", "latest"], "id": 9999
    }
    requests.post(RPC, json=payload)
    # Each call: contractStateCache miss -> findStorageBatch(1500 slots) -> DB query
    time.sleep(2)
```

Observe DB query logs showing repeated `SELECT slot, value FROM contract_state WHERE contract_id = ? AND slot IN (?, ?, ... [1500 params])` every 2 seconds from a single attacker request.

### Citations

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
