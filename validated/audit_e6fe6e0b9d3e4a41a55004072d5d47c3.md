All three core claims are verified against the actual source code. Here is the audit report:

---

Audit Report

## Title
Unbounded Batch Query Amplification via Per-Contract Slot Key Cache Poisoning in `findStorageBatch()`

## Summary
`ContractStateServiceImpl.findStorageBatch()` unconditionally issues a DB `IN` query containing every slot key accumulated in the per-contract Caffeine cache (up to `maximumSize=1500`) on every invocation, regardless of how many keys are actually needed. Because non-existent slots are never written to `contractStateCache`, they never short-circuit the batch path, allowing an attacker to permanently inflate every DB query for a target contract to 1500 bind parameters with a one-time poisoning step.

## Finding Description

**Verified code location**: `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`

**Verified cache configuration** (`web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java`):
- `contractSlots`: `expireAfterAccess=5m,maximumSize=3000` — outer cache mapping `contractId → per-contract CaffeineCache`
- `slotsPerContract`: `expireAfterAccess=5m,maximumSize=1500` — per-contract cache mapping `ByteBuffer(slotKey) → EMPTY_VALUE`
- `contractState`: `expireAfterWrite=2s,maximumSize=25000` — maps `(contractId, slotKey) → value`

**Flaw 1 — Unconditional full-set batch query** (lines 90–103):

Every call to `findStorageBatch()` adds the requested key via `putIfAbsent`, then immediately snapshots the *entire* key set of the per-contract cache and passes all of it to the repository:

```java
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
// ... builds cachedSlots from ALL keys ...
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
``` [1](#0-0) 

There is no filtering of keys whose values are already known or whose slots do not exist.

**Flaw 2 — Non-existent slots never populate `contractStateCache`** (lines 106–114):

Only slots *returned by the DB* are written to `contractStateCache`. A slot absent from `contract_state` is never cached:

```java
for (final var contractSlotValue : contractSlotValues) {
    contractStateCache.put(generateCacheKey(contractId, slotKey), slotValue);
    ...
}
``` [2](#0-1) 

Because `findStorage()` only short-circuits when `contractStateCache.get(...)` returns a non-null, non-`EMPTY_VALUE` result (line 63–67), non-existent slots always fall through to `findStorageBatch()`: [3](#0-2) 

**Flaw 3 — Per-contract cache retains poisoned keys for 5 minutes**:

`slotsPerContract = "expireAfterAccess=5m,maximumSize=1500"` — once 1500 non-existent keys are inserted, they persist for 5 minutes after last access. Repeated attacker calls refresh the access time, sustaining the poisoned state indefinitely. [4](#0-3) 

The repository query that gets amplified is:

```sql
SELECT slot, value FROM contract_state
WHERE contract_id = :contractId AND slot IN (:slots)
``` [5](#0-4) 

## Impact Explanation
Every `findStorage()` cache miss for a poisoned contract issues a `SELECT ... WHERE slot IN (?, ?, ..., ?)` with up to 1500 bind parameters instead of 1 — a **1500× amplification** of DB read load per cache miss. Because `contractStateCache` has a 2-second TTL, legitimate users querying the same contract are continuously subjected to these oversized queries after every expiry cycle. With up to 3000 contracts in the outer cache, the aggregate DB load can degrade query performance for all users of the mirror node.

## Likelihood Explanation
The attack requires no credentials, no privileged access, and no on-chain funds beyond a one-time contract deployment (a few HBAR). The public `POST /api/v1/contracts/call` endpoint is the only entry point. A single `eth_call` with a loop-SLOAD contract can inject all 1500 poisoned keys in one request. The exploit is fully scriptable and can be sustained indefinitely by periodically refreshing the per-contract cache entries. This is not a simple volumetric DDoS — it exploits a specific code flaw (missing negative caching) to amplify the DB cost of every subsequent legitimate request.

## Recommendation

1. **Negative-cache non-existent slots**: After the batch query returns, write a sentinel value (e.g., `EMPTY_VALUE`) to `contractStateCache` for every key in `cachedSlots` that was *not* returned by the DB. Update the `findStorage()` check to treat `EMPTY_VALUE` in `contractStateCache` as a definitive "not found" result, skipping `findStorageBatch()` entirely.

2. **Filter already-cached keys before building the batch**: Before constructing `cachedSlots`, check each key against `contractStateCache` and exclude keys whose values are already known (including the negative-cache sentinel). This prevents the batch from growing with keys that have already been resolved.

3. **Consider bounding the per-contract cache key set used per query**: Rather than passing the entire snapshot of the per-contract cache to every batch query, limit the batch to only the keys that are genuinely unknown at query time.

## Proof of Concept

**Step 1 — Poison**: Deploy a Hedera contract with a Solidity function that executes `SLOAD` in a loop over 1500 distinct storage slot indices supplied via calldata. Submit one `POST /api/v1/contracts/call` with calldata encoding 1500 distinct non-existent slot indices. The EVM calls `findStorage()` 1500 times; each miss calls `findStorageBatch()`, accumulating all 1500 keys in the per-contract `slotsPerContract` cache.

**Step 2 — Sustain**: Every ~4 minutes, re-submit the same call to refresh `expireAfterAccess` on the 1500 cache entries, keeping the poisoned state alive indefinitely.

**Step 3 — Amplify**: Any subsequent `eth_call` by any user that reads even a single slot of the poisoned contract will miss `contractStateCache` (2s TTL) and trigger `findStorageBatch()` with all 1500 keys in the SQL `IN` clause. The attacker's cost is one periodic refresh call; the DB cost imposed on every legitimate user is 1500× the normal query size.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L63-69)
```java
        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L90-103)
```java
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
