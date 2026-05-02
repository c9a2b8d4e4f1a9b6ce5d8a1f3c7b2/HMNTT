### Title
Cache TTL Asymmetry in `findStorageBatch()` Enables Unauthenticated DB Query Amplification DoS

### Summary
An unprivileged external user can exploit the asymmetric TTL between `contractSlotsCache`/`slotsPerContract` (expireAfterAccess=5m) and `contractStateCache` (expireAfterWrite=2s) in `ContractStateServiceImpl`. By first populating the per-contract slot key list with up to 1,500 entries, then repeatedly querying any single slot after the 2-second state cache expires, the attacker forces `findStorageBatch()` to issue a DB query containing all 1,500 cached slot keys on every cache miss — indefinitely, every 2 seconds — with no per-contract or per-slot rate control.

### Finding Description

**Code location:** `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, `findStorage()` lines 58–70, `findStorageBatch()` lines 85–122.

**Cache configuration (from `CacheProperties.java`):**
- `contractSlots` (maps contractId → per-contract CaffeineCache): `expireAfterAccess=5m, maximumSize=3000`
- `slotsPerContract` (per-contract slot key list): `expireAfterAccess=5m, maximumSize=1500`
- `contractState` (maps (contractId, slotKey) → value): `expireAfterWrite=2s, maximumSize=25000`

**Root cause — failed assumption:** The design assumes that the `slotsPerContract` cache acts as a "preload hint" list whose entries are only useful while the corresponding `contractStateCache` entries are alive. In reality, `slotsPerContract` entries survive for 5 minutes while `contractStateCache` entries expire every 2 seconds. The code never clears or shrinks the slot key list when `contractStateCache` entries expire.

**Exploit flow:**

*Phase 1 — Slot list inflation (one-time, ~1500 requests):*
The attacker calls the public web3 JSON-RPC endpoint (`eth_call`) targeting a contract, cycling through 1,500 distinct storage slot keys. Each call misses `contractStateCache` and enters `findStorageBatch()`:

```java
// Line 90: slot key is added to the per-contract list on every miss
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
// Line 91: ALL currently cached slot keys are collected
final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
// Line 103: DB query issued with the full growing list
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
```

After 1,500 requests the `slotsPerContract` cache for contract C holds 1,500 slot keys. These persist for 5 minutes from last access.

*Phase 2 — Sustained amplification (1 request every ≥2 seconds):*
The attacker sends a single request for any slot of contract C. Because `contractStateCache` expired (2s TTL), `findStorage()` misses at line 63 and calls `findStorageBatch()`. `findStorageBatch()` reads all 1,500 keys from `slotsPerContract` (line 91) and issues one DB query with a 1,500-element `IN` clause (line 103). The results are written back to `contractStateCache` (line 109), which expires again in 2 seconds. The cycle repeats indefinitely.

**Why existing checks are insufficient:**
- The global rate limiter (`requestsPerSecond=500`, `ThrottleManagerImpl`) counts HTTP requests, not DB slot lookups. One allowed request triggers a 1,500-slot batch query.
- The gas throttle (`gasPerSecond`) limits EVM gas, not DB I/O.
- There is no per-contract request rate limit, no cap on the batch query size, and no mechanism to evict `slotsPerContract` entries when `contractStateCache` entries expire.
- The `maximumSize=3000` on `contractSlotsCache` allows the attack to be replicated across up to 3,000 contracts simultaneously, multiplying the DB load.

### Impact Explanation
Each attacker request (within the 500 req/s global limit) can force a DB `SELECT ... WHERE slot IN (...)` with up to 1,500 parameters. At the allowed rate of 500 req/s, this translates to up to 750,000 effective slot lookups per second against the database. Across 3,000 contracts (the `contractSlotsCache` maximum), the theoretical DB amplification reaches 2.25 billion slot lookups per second from a single attacker. Even a fraction of this load is sufficient to saturate the PostgreSQL connection pool and degrade or halt the web3 service for all users, constituting a denial-of-service against the mirror node's contract call processing capacity.

### Likelihood Explanation
The web3 JSON-RPC endpoint is publicly accessible with no authentication. The attacker needs only standard HTTP tooling (e.g., `curl`, `web3.py`). Phase 1 requires ~1,500 requests (achievable in under 3 seconds at the 500 req/s limit). Phase 2 requires one request every 2 seconds. The attack is trivially automatable, repeatable indefinitely, and requires no privileged access, special knowledge of the contract, or on-chain transactions. The slot keys can be guessed (sequential integers are common EVM storage patterns) or enumerated from public blockchain data.

### Recommendation
1. **Bound batch query size:** Cap the number of slots passed to `findStorageBatch()` (e.g., 50–100) regardless of how many are in `slotsPerContract`.
2. **Align TTLs or link eviction:** When a `contractStateCache` entry expires, remove the corresponding key from `slotsPerContract`, or use `expireAfterWrite` on `slotsPerContract` with a TTL ≤ `contractState` TTL.
3. **Add per-contract rate limiting:** Throttle the number of `findStorageBatch()` invocations per contract per second independently of the global request rate.
4. **Limit slot list growth rate:** Restrict how many new slot keys a single request can add to `slotsPerContract` (currently unbounded per request).

### Proof of Concept

```python
import requests, time

RPC = "http://<mirror-node>/api/v1/contracts/call"
CONTRACT = "0x<target_contract_address>"

# Phase 1: populate slotsPerContract with 1500 distinct slot keys
# Each eth_call reads a different storage slot (e.g., via a getter that reads slot N)
for i in range(1500):
    slot_selector = f"0x{i:064x}"  # encodes slot index i as calldata
    requests.post(RPC, json={
        "to": CONTRACT,
        "data": slot_selector,
        "block": "latest"
    })

print("Slot list populated. Starting amplification phase...")

# Phase 2: one request every 2s triggers a 1500-slot batch DB query
while True:
    t0 = time.time()
    requests.post(RPC, json={
        "to": CONTRACT,
        "data": "0x" + "00" * 32,  # any slot
        "block": "latest"
    })
    elapsed = time.time() - t0
    # Wait just over 2s so contractStateCache has expired before next request
    time.sleep(max(0, 2.1 - elapsed))
    # Each iteration forces findStorageBatch() with 1500 slots against the DB
```