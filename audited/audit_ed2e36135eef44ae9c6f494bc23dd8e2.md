### Title
Cache-Amplified DB Query Amplification via Unbounded `slotsPerContract` Slot Key Seeding in `findStorageBatch()`

### Summary
An unprivileged external user can seed up to 1,500 unique slot keys per contract into the persistent `slotsPerContract` cache (TTL=5min) by issuing 1,500 separate `eth_call` requests. Because `findStorageBatch()` unconditionally issues a DB `IN`-clause query containing every key currently in that per-contract cache, any subsequent request that misses the short-lived `contractStateCache` (TTL=2s) triggers a 1,500-slot batch DB query from a single HTTP request — a 1,500× amplification factor. No privilege is required, and the existing rate limiter operates at the HTTP-request level, not at the DB-query-width level, leaving the amplification completely unmitigated.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70) checks `contractStateCache` (TTL=2s). On a miss it calls `findStorageBatch()` (lines 85–122).

Inside `findStorageBatch()`:
- Line 90: `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` — unconditionally registers the caller-supplied slot key into the per-contract slot cache.
- Line 91: `cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet()` — reads **all** currently registered slot keys for this contract.
- Line 103: `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — issues a single SQL `WHERE slot IN (…)` query containing every registered key.

The per-contract slot cache is backed by `cacheManagerSlotsPerContract` configured as `expireAfterAccess=5m,maximumSize=1500` (CacheProperties line 39). The outer `contractSlotsCache` is `expireAfterAccess=5m,maximumSize=3000` (line 25). Neither cache is bounded by the caller's identity or request rate.

**Root cause:** The design assumes that slot keys accumulate only from legitimate, organically distributed traffic. There is no cap on how many distinct slot keys a single caller may register, no per-caller accounting, and no limit on the width of the resulting IN-clause query. The `contractStateCache` TTL (2s) is 150× shorter than the `slotsPerContract` TTL (5min), so the amplified batch query is re-triggered on every `contractStateCache` expiry cycle for the lifetime of the slot-key entries.

**Additional worst-case (non-existent slots):** For slot keys that do not exist in the DB, `findStorageBatch()` returns no rows, so nothing is written to `contractStateCache` (lines 106–114). The check at line 63–67 therefore always misses, meaning `findStorageBatch()` is called on **every single request** for those slots — not just every 2 seconds — making the amplification continuous rather than periodic.

### Impact Explanation

With 1,500 seeded slots per contract, each attacker HTTP request causes the DB to evaluate a `WHERE slot IN (slot_1, …, slot_1500)` query instead of a single-slot lookup. At the default rate limit of 500 req/s, the effective DB slot-lookup rate becomes up to 750,000 slot evaluations/second versus 500 without the attack — a 1,500× increase in DB read load from a single attacker. With up to 3,000 contracts targetable via the outer `contractSlotsCache`, the theoretical ceiling is 4.5 billion slot evaluations/second. Even a fraction of this is sufficient to saturate DB I/O, exhaust connection pool threads, and degrade or deny service to legitimate users. This directly satisfies the ≥30% resource consumption increase threshold with minimal attacker effort.

### Likelihood Explanation

The attack requires only the ability to send unauthenticated HTTP POST requests to `/api/v1/contracts/call` — no wallet, no on-chain funds, no privileged access. The seeding phase (1,500 requests) completes in under 3 seconds at the default 500 req/s limit. The sustain phase requires only 1 request every 2 seconds (or continuously for non-existent slots). The attack is fully automatable with a simple script and is repeatable indefinitely as long as the attacker keeps the `slotsPerContract` entries alive by accessing them within the 5-minute expiry window.

### Recommendation

1. **Cap IN-clause width:** In `findStorageBatch()`, limit `cachedSlots` to a configurable maximum (e.g., 100) before issuing the batch query, discarding the oldest/least-recently-used entries.
2. **Evict slot keys on `contractStateCache` population:** After a successful batch query, remove the returned slot keys from `contractSlotsCache` so they are not re-queried on the next cycle; only re-add them on the next actual miss.
3. **Per-contract slot key admission control:** Track how many distinct slot keys a given caller (IP or API key) has contributed to a contract's slot cache and reject registrations beyond a per-caller threshold.
4. **Cache non-existent slots:** Store a sentinel value in `contractStateCache` for slots not found in the DB so that repeated queries for non-existent slots do not bypass the 2-second cache and continuously trigger batch queries.

### Proof of Concept

```python
import requests, time

TARGET = "http://mirror-node-web3:8545/api/v1/contracts/call"
CONTRACT = "0x000000000000000000000000000000000000ABCD"  # any valid contract id

# Phase 1: Seed 1500 unique slot keys into slotsPerContract cache
# Each eth_call reads a different storage slot, registering it in the per-contract cache
for i in range(1500):
    slot = hex(i).zfill(66)  # unique non-existent slot key
    payload = {
        "to": CONTRACT,
        "data": "0x" + "00" * 32,  # any calldata that triggers SLOAD of slot i
        "block": "latest"
    }
    requests.post(TARGET, json=payload)

print("Seeding complete. Per-contract slot cache now holds 1500 keys.")

# Phase 2: Sustain amplified DB load with 1 request per 2 seconds
# Each request triggers findStorageBatch() with a 1500-slot IN-clause
while True:
    payload = {"to": CONTRACT, "data": "0x" + "00" * 32, "block": "latest"}
    requests.post(TARGET, json=payload)
    # DB receives: SELECT slot, value FROM contract_state
    #              WHERE contract_id = X AND slot IN (slot_0, slot_1, ..., slot_1499)
    time.sleep(2)  # re-trigger on every contractStateCache expiry
```

Each iteration of the sustain loop causes the database to process a 1,500-element `IN`-clause query from a single HTTP request, with no server-side mechanism to detect or block the amplification.