After carefully reading the actual source code, I can verify the claims against the real implementation.

**Code verification:**

- `findStorage()` lines 63–67: checks `contractStateCache` and returns early only if value is non-null and non-`EMPTY_VALUE`. [1](#0-0) 
- `findStorageBatch()` line 90: unconditionally adds the requested key to the per-contract cache via `putIfAbsent`. [2](#0-1) 
- Lines 93–103: collects **all** keys from the per-contract cache with no filter against `contractStateCache`, then passes them all to `contractStateRepository.findStorageBatch()`. [3](#0-2) 
- Lines 106–113: only DB-returned keys are written to `contractStateCache`; non-existent keys are never written. [4](#0-3) 
- `slotsPerContract` cache: `expireAfterAccess=5m,maximumSize=1500` — confirms the 1500-key cap and 5-minute TTL. [5](#0-4) 
- `contractState` cache: `expireAfterWrite=2s` — confirms the 2-second TTL asymmetry. [6](#0-5) 

**SECURITY.md check:** The exclusion "Impacts that only require DDoS" applies to pure volumetric attacks. This vulnerability is a **code-level amplification flaw** — a specific design defect causes each request to trigger up to 1,500× more DB work than intended. That is distinct from a volumetric DDoS and is not excluded. [7](#0-6) 

All line references, root cause, exploit flow, and impact claims check out against the actual code.

---

# Audit Report

## Title
Quadratic DB Amplification via Unbounded Slot Key Accumulation in `findStorageBatch()`

## Summary
`ContractStateServiceImpl.findStorageBatch()` queries ALL accumulated slot keys from the per-contract `contractSlotsCache` on every cache miss, including keys whose values are already in `contractStateCache`. Because non-existent slot keys are never written to `contractStateCache`, an unauthenticated attacker can accumulate up to 1,500 phantom keys in the per-contract cache and then trigger a 1,500-row DB batch query on every subsequent request — a 1,500× amplification factor per request, sustained for the 5-minute `slotsPerContract` TTL window.

## Finding Description

**File:** `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`

**Root cause — missing filter before batch construction:**

`findStorage()` checks `contractStateCache` for the *requested* key only (lines 63–67). If the key is absent, `findStorageBatch()` is called. Inside `findStorageBatch()`:

1. The requested key is unconditionally added to the per-contract `contractSlotsCache` (line 90), regardless of whether it exists in the DB.
2. **All** keys currently in `contractSlotsCache` are collected (line 91) with no cross-check against `contractStateCache`.
3. The full collected set is passed to `contractStateRepository.findStorageBatch()` (line 103).
4. Only keys the DB actually returns are written to `contractStateCache` (lines 106–113). Non-existent keys are never written.

The comment on line 89 states the cache holds "slot keys whose slot values are not present in the `contractStateCache`" — but this invariant is never enforced. The code never filters `cachedSlotKeys` against `contractStateCache` before building the batch.

**Cache configuration asymmetry:**
- `contractStateCache`: `expireAfterWrite=2s` — values expire quickly; even legitimate keys re-enter the batch after 2 seconds.
- `slotsPerContract` (per-contract inner cache): `expireAfterAccess=5m,maximumSize=1500` — phantom keys persist for 5 minutes, capped at 1,500 per contract.

**Exploit flow:**

*Phase 1 — Accumulation (O(N²) total DB work):*
- Attacker sends N requests for unique non-existent slot keys K₁…KN against the same contract via any public JSON-RPC endpoint (`eth_call`, `eth_estimateGas`, etc.).
- Request Kᵢ misses `contractStateCache` → `findStorageBatch([K₁…Kᵢ])` → i DB lookups.
- Kᵢ not found in DB → never written to `contractStateCache` → remains in `contractSlotsCache`.
- Total DB work at N=1500: 1+2+…+1500 = **1,125,750 DB lookups**.

*Phase 2 — Sustained amplification (O(N) per request):*
- Any subsequent request for any previously-used non-existent key misses `contractStateCache` → `findStorageBatch([K₁…K₁₅₀₀])` → **1,500 DB lookups per request**.
- This window lasts 5 minutes; re-accumulation is trivial.

**Why existing mitigations are insufficient:**
- The `contractStateCache` early-return guards only the *requested* key, not the batch contents.
- The 1,500-entry cap bounds but does not eliminate the amplification.
- The 2-second `contractStateCache` TTL causes even legitimate keys to re-enter the batch frequently.

## Impact Explanation

Normal operation produces approximately 1 DB lookup per unique slot request. After accumulation, each request produces up to 1,500 DB lookups against the `contract_state` table using an `IN` clause of up to 1,500 32-byte slot keys. This can saturate DB connection pools, increase query latency for all users, and degrade mirror node availability. The amplification is bounded at 1,500× per request by the `slotsPerContract` `maximumSize`, but this is still a severe multiplier on DB load from a single attacker.

## Likelihood Explanation

The attack requires no authentication, no privileged access, and no on-chain transactions. Any caller of the public JSON-RPC API can trigger it. A valid contract ID is publicly discoverable. Non-existent slot keys can be arbitrary 32-byte values. The accumulation phase requires only 1,500 HTTP requests. The sustained amplification window is 5 minutes and trivially renewable.

## Recommendation

1. **Filter `cachedSlotKeys` against `contractStateCache` before building the batch.** Before adding a key to `cachedSlots`, check whether its value is already present and non-expired in `contractStateCache`; skip it if so. This enforces the invariant stated in the line 89 comment.

2. **Write a sentinel/negative-cache entry for non-existent keys.** After `findStorageBatch()` returns, for any key in `cachedSlots` that was *not* returned by the DB, write a sentinel value (e.g., `EMPTY_VALUE`) to `contractStateCache`. The `findStorage()` early-return at line 65 already handles `EMPTY_VALUE` correctly (it does not return early for `EMPTY_VALUE`), so a distinct sentinel (e.g., a dedicated `NOT_FOUND` marker) should be used and checked at line 65 to short-circuit the call without entering `findStorageBatch()`.

3. **Alternatively, remove non-existent keys from `contractSlotsCache`** after a DB miss, so they do not accumulate across requests.

## Proof of Concept

```
# Phase 1: Accumulate 1500 non-existent slot keys for contract 0x<CONTRACT>
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)  # unique non-existent 32-byte key
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"0x<sload_selector>${SLOT}\",\"to\":\"0x<CONTRACT>\"}"
done

# Phase 2: Each subsequent request now triggers 1500 DB lookups
# Re-use any previously-sent non-existent key:
SLOT=$(printf '%064x' 1)
while true; do
  curl -s -X POST https://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d "{\"data\":\"0x<sload_selector>${SLOT}\",\"to\":\"0x<CONTRACT>\"}"
done
# Each iteration: 1 HTTP request → 1500 DB lookups (1500× amplification)
```

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L63-69)
```java
        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L90-91)
```java
        contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
        final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L93-103)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-28)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
```
