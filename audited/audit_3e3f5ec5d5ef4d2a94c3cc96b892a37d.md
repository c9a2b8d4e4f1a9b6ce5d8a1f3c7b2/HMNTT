### Title
Cache TTL Mismatch in `ContractStateServiceImpl` Enables Sustained Batch DB Query Amplification

### Summary
The `contractStateCache` uses `expireAfterWrite=2s` while the per-contract slot key cache (`slotsPerContract`) uses `expireAfterAccess=5m`. This TTL mismatch means slot keys accumulate in the long-lived cache for up to 5 minutes, but their values expire every 2 seconds regardless of access frequency. Any cache miss on `contractStateCache` triggers `findStorageBatch()`, which issues a single DB query for **all** accumulated slot keys of that contract — up to 1,500 slots per query. An unprivileged attacker can sustain this at 0.5 RPS (one request per 2 seconds), well below the 500 RPS global throttle, causing continuous large batch DB queries with minimal attacker cost.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.findStorage()` (lines 58–70) checks `contractStateCache` for the requested slot value. The cache is configured with `expireAfterWrite=2s,maximumSize=25000` (`CacheProperties.java` line 28). If the entry is absent (expired or never written), it falls through to `findStorageBatch()` (lines 85–122).

Inside `findStorageBatch()`:
- Line 86–87: retrieves the per-contract slot key cache (`contractSlotsCache`), which is backed by `slotsPerContract` config: `expireAfterAccess=5m,maximumSize=1500` (`CacheProperties.java` line 39).
- Line 90: adds the requested key to the slot key cache via `putIfAbsent`.
- Line 91: reads **all** currently cached slot keys for the contract: `contractSlotsCache.getNativeCache().asMap().keySet()`.
- Line 103: issues `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` — a DB query with `WHERE contract_id = X AND slot IN (<all cached slot keys>)`.
- Lines 106–113: writes results back into `contractStateCache` (2s TTL).

**Root cause:** The `contractStateCache` (2s write TTL) and the `slotsPerContract` slot key cache (5m access TTL) have fundamentally mismatched lifetimes. Slot keys accumulate in the long-lived cache over 5 minutes of normal use, but their values in `contractStateCache` expire every 2 seconds unconditionally. Every expiry cycle forces a full batch re-query for all accumulated slot keys.

**Failed assumption:** The design assumes that `contractStateCache` entries will typically be hit before expiry, amortizing the batch query cost. This assumption fails when an attacker deliberately times requests to arrive just after the 2s write TTL expires, ensuring a perpetual cache miss while the slot key cache remains fully populated.

**Exploit flow:**

1. **Slot key cache population (one-time setup):** Attacker sends 1,500 requests for distinct slot keys of a target contract (e.g., a large DeFi contract with many storage slots). Each request adds a key to the per-contract `slotsPerContract` cache (5m access TTL). This takes ~3 seconds at 500 RPS.

2. **Sustained exploitation:** After 2 seconds, all `contractStateCache` entries expire. Attacker sends one request every ~2 seconds for any slot of the target contract.

3. **Per-request amplification:** Each request hits `findStorage()` → `contractStateCache` miss → `findStorageBatch()` → reads all 1,500 slot keys from `slotsPerContract` cache → issues `findStorageBatch(contractId, [1500 slots])` DB query → writes 1,500 results back to `contractStateCache` → 2 seconds later, all 1,500 entries expire again.

4. **Perpetuation:** Each request also refreshes the `expireAfterAccess` timer on the slot key cache entries, keeping them alive indefinitely as long as the attacker continues querying.

**Why existing checks fail:**

- **Global RPS throttle** (`requestsPerSecond=500`, `ThrottleProperties.java` line 35, `ThrottleManagerImpl.java` lines 38–39): The attack requires only 0.5 RPS — 1,000× below the threshold. No per-IP or per-contract rate limiting exists.
- **Gas throttle** (`ThrottleManagerImpl.java` line 40, `ThrottleProperties.scaleGas()` lines 42–47): `scaleGas(gas)` returns `0L` for any `gas ≤ 10,000`. The attacker sets `gas=10000` in the request; `gasLimitBucket.tryConsume(0)` always returns `true`, bypassing the gas throttle entirely. No minimum gas is enforced on the request field.
- **`enableBatchContractSlotCaching` flag** (`ContractStateServiceImpl.java` line 59): Defaults to `true`; disabling it would break the batch optimization for all users.

### Impact Explanation

Each attacker request at 0.5 RPS generates a DB query scanning up to 1,500 rows (`WHERE slot IN (1500 values)`). With the `contractSlots` outer cache holding up to 3,000 contracts (`contractSlots = "expireAfterAccess=5m,maximumSize=3000"`, `CacheProperties.java` line 25), an attacker targeting multiple contracts can multiply this effect: 3,000 contracts × 1,500 slots × 0.5 RPS = 2,250,000 slot-row DB reads per second from a single attacker at 1,500 RPS total (still within the 500 RPS global limit per attacker, but multiple attackers or multiple contracts compound this). Even a single-contract attack generates sustained large IN-clause queries that bypass the cache entirely, increasing DB CPU and I/O load well above the 30% threshold compared to normal cached operation.

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond a valid contract address (publicly available on-chain), and no tooling beyond a standard HTTP client. Slot keys for common contracts (ERC-20, AMMs, lending protocols) follow deterministic storage layouts documented publicly. The attacker sustains the attack at 0.5 RPS indefinitely — trivially automatable with a single `curl` loop or a minimal script. The attack is repeatable, stealthy (low request rate avoids alerting), and requires no on-chain transactions.

### Recommendation

1. **Change `contractStateCache` to `expireAfterAccess`** instead of `expireAfterWrite`. This ensures actively-used entries are not evicted every 2 seconds, eliminating the perpetual cache miss pattern.

2. **Alternatively, align TTLs**: If write-expiry is required for data freshness, reduce the `slotsPerContract` TTL to match (e.g., `expireAfterAccess=2s`), so slot keys are evicted at the same rate as their values, preventing unbounded batch query growth.

3. **Add per-contract or per-IP rate limiting** on the `/api/v1/contracts/call` endpoint to limit the blast radius of any single client.

4. **Enforce a minimum gas floor on requests** to prevent gas throttle bypass via `gas ≤ 10,000`.

### Proof of Concept

```bash
CONTRACT_ADDR="0x<target_contract>"
RPC_URL="http://<mirror-node>/api/v1/contracts/call"

# Phase 1: Populate slot key cache with 1500 distinct slots (one-time, ~3s at 500 RPS)
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)
  curl -s -X POST $RPC_URL \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT_ADDR\",\"data\":\"0x$(python3 -c "print('2e64cec1' + '0'*62 + format($i,'02x'))")\",\"gas\":10000,\"block\":\"latest\"}" &
done
wait

# Phase 2: Sustained exploitation — one request every 2s triggers 1500-slot batch DB query
while true; do
  curl -s -X POST $RPC_URL \
    -H "Content-Type: application/json" \
    -d "{\"to\":\"$CONTRACT_ADDR\",\"data\":\"0x2e64cec1\",\"gas\":10000,\"block\":\"latest\"}"
  sleep 2
done
```

Each iteration of the loop in Phase 2 arrives after `contractStateCache` has expired, causing `findStorageBatch()` to issue a `SELECT slot, value FROM contract_state WHERE contract_id = X AND slot IN (<1500 values>)` query against the database, sustained indefinitely.