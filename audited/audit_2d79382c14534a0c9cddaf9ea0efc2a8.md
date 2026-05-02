### Title
Cache TTL Mismatch Enables Sustained DB Amplification via `findStorageBatch()` Slot Key Accumulation

### Summary
The `contractStateCache` expires slot values after 2 seconds (write-based), while the `slotsPerContract` cache retains slot keys for 5 minutes (access-based). Every cache miss in `contractStateCache` triggers `findStorageBatch()`, which unconditionally queries the DB for **all** accumulated slot keys in `slotsPerContract`. An unprivileged attacker can fill the per-contract slot key cache to its 1500-entry maximum, then sustain a 1500-slot batch DB query every 2 seconds indefinitely by periodically re-accessing slots to reset their TTL — achieving up to a 1500x DB query amplification factor within the allowed rate limit.

### Finding Description

**Code path**: `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`, `findStorageBatch()`, lines 85–122.

**Cache configuration mismatch** (root cause):
- `contractState`: `expireAfterWrite=2s, maximumSize=25000` — slot values expire 2 seconds after being written
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — slot keys expire 5 minutes after last access
- `contractSlots`: `expireAfterAccess=5m, maximumSize=3000` — outer cache mapping contractId → per-contract cache

**Exploit flow**:

1. **Setup**: Attacker sends 1500 contract calls, each accessing a distinct slot key of the same contract. Each call reaches `findStorageBatch()` (because `contractStateCache` is empty), which executes `contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE)` (line 90), accumulating all 1500 slot keys in the `slotsPerContract` cache.

2. **Trigger loop**: After 2 seconds, all slot values expire from `contractStateCache`. The attacker sends a single contract call for any slot of that contract. `findStorage()` (line 63) finds no cached value and calls `findStorageBatch()`. At line 91, `contractSlotsCache.getNativeCache().asMap().keySet()` returns all 1500 still-cached slot keys. Line 103 issues:
   ```sql
   SELECT slot, value FROM contract_state WHERE contract_id = :contractId AND slot IN (:slots)
   ```
   with all 1500 slots as parameters — a single large DB query per attacker request.

3. **TTL reset**: `putIfAbsent(wrappedKey, EMPTY_VALUE)` at line 90 is a write operation on the Caffeine cache; in `expireAfterAccess` mode, any access (read or write) resets the TTL for that entry. To keep all 1500 keys alive, the attacker cycles through them within the 5-minute window: 1500 keys / 300 seconds = 5 requests/second minimum, well within the 500 req/s rate limit.

4. **Sustained state**: The attacker maintains the full 1500-slot batch query indefinitely by cycling through slot accesses at ~5 req/s, while each cycle triggers a 1500-slot DB query every 2 seconds.

**Why checks fail**:
- `ThrottleManagerImpl.throttle()` (lines 37–48) enforces `requestsPerSecond=500` and `gasPerSecond` limits. Neither is proportional to the number of DB slots queried per request. A minimal-gas call (21,000 gas, which `scaleGas()` rounds to 0 tokens consumed per line 43–44 of `ThrottleProperties`) can trigger a 1500-slot batch query.
- There is no per-contract rate limit, no cap on the batch size passed to `findStorageBatch()`, and no check on how many slot keys are accumulated in `slotsPerContract` before issuing the DB query.

### Impact Explanation

Each attacker request causes a DB `IN` query over up to 1500 slots — a 1500x amplification factor. At 500 req/s (the rate limit), the attacker can force up to 750,000 DB slot lookups per second. Even at a fraction of the rate limit (5 req/s to maintain TTLs + periodic bursts), the sustained batch queries represent a disproportionate DB load increase well exceeding the 30% threshold. The `contract_state` table is queried with large `IN` clauses repeatedly, degrading query planner performance and consuming DB connection pool resources.

### Likelihood Explanation

No privileges are required — any caller of the public `/api/v1/contracts/call` endpoint can trigger this. The setup phase (1500 requests) is a one-time cost. The sustain phase requires only ~5 req/s, which is invisible against the 500 req/s rate limit. The attack is fully repeatable, automatable with a simple script, and requires no special knowledge beyond knowing a valid contract address and any 1500 distinct storage slot indices (which can be enumerated or guessed as sequential integers).

### Recommendation

1. **Cap batch size before querying**: In `findStorageBatch()`, limit the number of slot keys passed to `findStorageBatch()` to a configurable maximum (e.g., 100) before issuing the DB query, regardless of how many keys are in `slotsPerContract`.
2. **Align cache TTLs**: Change `slotsPerContract` to `expireAfterWrite` instead of `expireAfterAccess`, so slot keys expire on a fixed schedule rather than being indefinitely renewable by the attacker.
3. **Gas-aware throttling for batch size**: Account for the number of cached slot keys when consuming gas tokens, or add a separate per-contract-per-second DB query budget.
4. **Consider `expireAfterWrite` for `contractSlots`**: The outer cache also uses `expireAfterAccess=5m`, compounding the problem.

### Proof of Concept

```
# Step 1: Fill slotsPerContract cache with 1500 unique slot keys for contract 0xTARGET
for i in $(seq 1 1500); do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"to\":\"0xTARGET\",\"data\":\"0x$(printf '%064x' $i)\",\"gas\":21000}" &
done
wait

# Step 2: Every 2 seconds, access any slot to trigger 1500-slot batch DB query
# (contractStateCache expires after 2s, slotsPerContract keys still alive for 5m)
while true; do
  curl -s -X POST http://mirror-node/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"to":"0xTARGET","data":"0x0000...0001","gas":21000}'
  sleep 2
done

# Step 3: In parallel, cycle through all 1500 slots at ~5 req/s to reset TTLs
# keeping all keys alive in slotsPerContract indefinitely
```

Each iteration of Step 2 causes `ContractStateRepository.findStorageBatch()` to execute with a 1500-element `IN` clause. DB query load is sustained indefinitely with no natural expiry.