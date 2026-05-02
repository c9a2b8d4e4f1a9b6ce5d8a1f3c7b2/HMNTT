I have verified all code references against the actual repository. Here is my assessment:

**Verification summary:**
- Line 90 `putIfAbsent` — confirmed [1](#0-0) 
- Batch DB query at line 103 — confirmed [2](#0-1) 
- Only DB-confirmed keys are written to `contractStateCache` (lines 106–113) — confirmed [3](#0-2) 
- Cache configs (`slotsPerContract=expireAfterAccess=5m,maximumSize=1500`, `contractState=expireAfterWrite=2s`) — confirmed [4](#0-3) 
- Global rate limiter is a single token bucket at 500 RPS, not per-IP/per-contract — confirmed [5](#0-4) 
- `enableBatchContractSlotCaching=true` by default — confirmed [6](#0-5) 

**One inaccuracy in the report:** The claim that `asMap().keySet()` iteration resets `expireAfterAccess` TTL for all entries in Caffeine is incorrect. In Caffeine's implementation, bulk iteration of the map view does **not** update per-entry access timestamps; only individual `get()`/`getIfPresent()` calls do. Bogus keys therefore expire after 5 minutes of no individual access, not "immortally." The attacker must re-inject every ~5 minutes. This reduces severity slightly but does not invalidate the vulnerability.

**SECURITY.md check:** The exclusion "Impacts that only require DDoS" does not apply here. This is a cache poisoning attack requiring only 1500 low-volume requests; the amplification is then carried by legitimate user traffic, not the attacker's own traffic. It is structurally distinct from a volumetric DDoS. [7](#0-6) 

---

# Audit Report

## Title
Unauthenticated Cache Pollution via Unbounded Slot Key Injection in `findStorageBatch()` Causes Sustained DB Query Amplification

## Summary
In `ContractStateServiceImpl.findStorageBatch()`, any caller-supplied slot key is unconditionally inserted into the per-contract `slotsPerContract` Caffeine cache before any database validation occurs. Because bogus (non-existent) slot keys never produce DB results, they are never promoted to `contractStateCache` and persist in the slot key tracking cache for up to 5 minutes. Every subsequent legitimate request for the same contract triggers a batch DB query that includes all attacker-injected bogus keys, amplifying DB load by up to 1500x per targeted contract.

## Finding Description

**File:** `web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java`
**Function:** `findStorageBatch()`, lines 85–122

**Root cause — line 90:**
```java
contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
```
This call unconditionally inserts the caller-supplied slot key into the per-contract Caffeine cache (`slotsPerContract`, configured `expireAfterAccess=5m, maximumSize=1500`) before any database query is issued. There is no check that the key corresponds to a slot that actually exists in `contract_state`. [8](#0-7) 

**Why bogus keys persist:**
After `putIfAbsent`, line 103 issues a batch query:
```java
final var contractSlotValues = contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
```
Only keys that actually exist in the DB are returned and subsequently stored in `contractStateCache` (lines 106–109). Bogus keys return no rows, so they are never written to `contractStateCache`. On the next legitimate request, `contractStateCache` (TTL `expireAfterWrite=2s`) has expired, `findStorage()` falls through to `findStorageBatch()` again, and the entire set of cached slot keys — including all bogus ones — is re-submitted to the DB. [9](#0-8) 

**Cache size configuration:**
- `contractSlots`: `expireAfterAccess=5m, maximumSize=3000` — top-level map of contractId → per-contract cache
- `slotsPerContract`: `expireAfterAccess=5m, maximumSize=1500` — per-contract slot key set
- `contractState`: `expireAfterWrite=2s, maximumSize=25000` — actual slot values (expires every 2 seconds) [10](#0-9) 

**Exploit flow:**
1. Attacker identifies a victim contract address (any publicly known contract).
2. Attacker sends up to 1500 `eth_call` or `eth_getStorageAt`-equivalent requests, each with a different random 32-byte slot key targeting the victim contract. No authentication is required.
3. Each request passes through `findStorage()` → `findStorageBatch()` → `putIfAbsent(bogusKey, EMPTY_VALUE)`. All 1500 bogus keys are now in the per-contract `contractSlotsCache`.
4. Every legitimate user request for any slot of that contract (after the 2-second `contractStateCache` TTL expires) triggers `findStorageBatch()`, which builds `cachedSlots` containing all 1500 bogus keys plus the 1 real key, and issues a single `WHERE slot IN (1501 values)` query to PostgreSQL.
5. Bogus keys expire after 5 minutes of no individual access. The attacker re-injects every ~5 minutes to sustain the attack.

**Why existing checks are insufficient:**
- The global rate limiter (`requestsPerSecond=500`) is a single global token bucket, not per-IP or per-contract. An attacker can inject 1500 bogus keys across 3 seconds (500 RPS × 3s) without triggering a throttle. [5](#0-4) 
- The `maximumSize=1500` LRU cap limits the amplification factor but does not prevent the attack.
- The `enableBatchContractSlotCaching` flag is `true` by default and is the only guard, but it is a feature flag, not a security control. [6](#0-5) 

## Impact Explanation
Every legitimate `eth_call` or storage read for a poisoned contract issues a PostgreSQL `WHERE slot IN (up to 1501 values)` query instead of a single-key lookup. With multiple targeted contracts (up to 3000 entries in `contractSlots`), an attacker can sustain elevated DB query complexity across the entire node. Wide `IN` clauses with non-indexed bogus keys force full or partial index scans on the `contract_state` table. This degrades response latency for all users of affected contracts and can exhaust DB connection pool capacity under sustained attack. **Severity: Medium** (availability impact; no data confidentiality or integrity loss). [11](#0-10) 

## Likelihood Explanation
The attack requires only HTTP access to the public web3 API endpoint — no credentials, no on-chain funds, no special knowledge beyond the target contract address. The 1500-key cap means the attacker needs only 1500 requests (achievable in ~3 seconds at the default 500 RPS global limit). The attack must be re-executed every ~5 minutes as bogus keys expire, but this is trivially automatable. **Likelihood: High.**

## Recommendation
1. **Validate before caching:** Only insert a slot key into `contractSlotsCache` after confirming it exists in the DB. Move the `putIfAbsent` call to after the `findStorageBatch` result is processed, inserting only keys that returned a DB row.
2. **Separate "miss" tracking:** If pre-caching of miss keys is desired for batching purposes, use a separate short-TTL (e.g., 2–5 seconds, matching `contractState` TTL) "pending" cache for unvalidated keys, preventing long-lived pollution.
3. **Per-contract slot injection rate limit:** Add a per-contract (or per-IP) rate limit on the number of distinct slot keys that can be inserted into `contractSlotsCache` within a time window.
4. **Cap batch query size independently of cache size:** Enforce a hard limit on the number of keys submitted per `findStorageBatch` call, independent of how many keys are in the cache.

## Proof of Concept
```python
import requests, os, json

TARGET_CONTRACT = "0x<victim_contract_address>"
RPC_URL = "http://<mirror-node>/api/v1/contracts/call"

# Step 1: Inject 1500 bogus slot keys into the per-contract cache
for i in range(1500):
    bogus_slot = "0x" + os.urandom(32).hex()
    payload = {
        "jsonrpc": "2.0", "method": "eth_getStorageAt",
        "params": [TARGET_CONTRACT, bogus_slot, "latest"],
        "id": i
    }
    requests.post(RPC_URL, json=payload)

# Step 2: Every subsequent legitimate request now triggers a
# WHERE slot IN (1501 values) query instead of a single-key lookup.
# Legitimate users experience amplified DB latency for ~5 minutes.
# Re-run Step 1 every 5 minutes to sustain the attack.
``` [12](#0-11)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** SECURITY.md (L44-44)
```markdown
- Impacts that only require DDoS.
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
