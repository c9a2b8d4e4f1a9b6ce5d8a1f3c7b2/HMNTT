Now I have all the information needed to make a precise determination. Let me trace the exact code flow:

**`findStorage()` (lines 58-70):** Checks `contractStateCache` first; if the key is found and non-empty, returns immediately. Only calls `findStorageBatch()` when the key is **not** in `contractStateCache`.

**`findStorageBatch()` (lines 85-122):** Adds the requested key to `contractSlotsCache` (per-contract Caffeine cache), then collects **ALL** keys from `contractSlotsCache` (line 91) — including those whose values are already in `contractStateCache` — and passes them all to `contractStateRepository.findStorageBatch()` (line 103).

**Critical asymmetry:** `contractStateCache` expires after 2 seconds (`expireAfterWrite=2s`), while `contractSlotsCache` persists for 5 minutes (`expireAfterAccess=5m`, max 1500 entries). Non-existent slot keys are never written to `contractStateCache` (line 106-113 only writes keys returned by DB), so they permanently trigger `findStorageBatch` on every request.

---

### Title
Quadratic DB Amplification via Unbounded Slot Key Accumulation in `findStorageBatch()`

### Summary
`ContractStateServiceImpl.findStorageBatch()` queries ALL accumulated slot keys from `contractSlotsCache` on every cache miss, including keys whose values are already in `contractStateCache`. Because non-existent slot keys are never written to `contractStateCache`, an unprivileged attacker can accumulate up to 1,500 phantom keys in the per-contract `contractSlotsCache` and then trigger a 1,500-row DB batch query on every subsequent request — a 1,500× amplification factor per request.

### Finding Description

**Exact code path:**

`ContractStateServiceImpl.java`, `findStorageBatch()`, lines 85–122:

```
line 90:  contractSlotsCache.putIfAbsent(wrappedKey, EMPTY_VALUE);
line 91:  final var cachedSlotKeys = contractSlotsCache.getNativeCache().asMap().keySet();
lines 93-101: ALL keys collected into cachedSlots (no filter against contractStateCache)
line 103: contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots);
lines 106-113: only DB-returned keys are written to contractStateCache
```

**Root cause:** The code comment on line 89 says "Cached slot keys for contract, whose slot values are not present in the contractStateCache" — but this is aspirational, not enforced. The code never filters `cachedSlotKeys` against `contractStateCache` before building the batch. Every call to `findStorageBatch` re-queries the entire accumulated key set from the DB.

**Failed assumption:** The design assumes that keys in `contractSlotsCache` will eventually be populated in `contractStateCache` and thus future calls will hit the `findStorage()` early-return at lines 63–67. This assumption breaks for non-existent slot keys: they are added to `contractSlotsCache` (line 90) but never written to `contractStateCache` (lines 106–113 only write keys the DB returns). They remain permanently in `contractSlotsCache` for 5 minutes.

**Exploit flow:**

*Phase 1 — Accumulation (O(N²) DB work):*
- Attacker sends N requests for unique, non-existent slot keys K₁…KN against the same contract via any public JSON-RPC endpoint (`eth_call`, `eth_estimateGas`, etc.)
- Request Kᵢ: not in `contractStateCache` → `findStorageBatch([K₁…Kᵢ])` → i DB lookups
- Kᵢ not found in DB → never written to `contractStateCache`
- Total DB work: 1+2+…+N = N(N+1)/2; at N=1500: **1,125,750 DB lookups**

*Phase 2 — Sustained amplification (O(N) per request):*
- Attacker repeatedly requests any previously-used non-existent key
- Each request: not in `contractStateCache` → `findStorageBatch([K₁…K₁₅₀₀])` → **1,500 DB lookups per request**
- `contractSlotsCache` TTL is 5 minutes, so this window is long-lived

**Why existing checks are insufficient:**

- The `contractStateCache` check at line 63 only guards the *requested* key, not the batch contents
- The `contractSlotsCache` max size of 1,500 bounds the batch size but still allows 1,500× amplification
- The `contractStateCache` 2-second TTL means even legitimately cached values expire quickly, causing real keys to also be re-queried in the batch
- Rate limiting (`requestsPerSecond=500`) does not prevent a single attacker from sustaining 500 × 1,500 = 750,000 DB lookups/second after accumulation

### Impact Explanation

Normal operation: ~1 DB lookup per unique slot request. After accumulation: 1,500 DB lookups per request. At the 500 req/s rate limit, this is a **1,500× increase in DB query volume** from a single attacker, far exceeding the 30% threshold. The PostgreSQL `contract_state` table is queried with an `IN` clause of up to 1,500 32-byte slot keys per call, causing sustained index scan amplification. This can saturate DB connection pools, increase query latency for all users, and degrade mirror node availability.

### Likelihood Explanation

The attack requires no authentication, no privileged access, and no on-chain transactions. Any caller of the public JSON-RPC API can trigger it. The attacker only needs to know a valid contract ID (publicly discoverable via `eth_getCode` or block explorers). Non-existent slot keys can be any 32-byte values. The accumulation phase requires only 1,500 HTTP requests, which is trivially achievable. The sustained phase can be maintained indefinitely within the 5-minute `contractSlotsCache` TTL window, and re-accumulation is trivial.

### Recommendation

Before building `cachedSlots` at lines 93–101, filter out keys already present in `contractStateCache`:

```java
for (var slot : cachedSlotKeys) {
    byte[] slotBytes = ((ByteBuffer) slot).array();
    // Only include in batch if not already cached
    SimpleKey ck = generateCacheKey(contractId, slotBytes);
    if (contractStateCache.get(ck, byte[].class) == null) {
        cachedSlots.add(slotBytes);
    }
    if (wrappedKey.equals(slot)) {
        isKeyEvictedFromCache = false;
    }
}
```

Additionally, consider not adding non-existent keys to `contractSlotsCache` (or marking them with a sentinel that prevents re-batching), and capping the per-request batch size independently of the accumulated cache size.

### Proof of Concept

```
# Prerequisites: mirror-node web3 service running, contract at address CONTRACT_ADDR

# Phase 1: Accumulate 1500 unique non-existent slot keys
for i in $(seq 1 1500); do
  SLOT=$(printf '%064x' $i)  # unique 32-byte hex slot key
  curl -s -X POST http://localhost:8545 \
    -H 'Content-Type: application/json' \
    -d "{\"jsonrpc\":\"2.0\",\"method\":\"eth_call\",\"params\":[{\"to\":\"CONTRACT_ADDR\",\"data\":\"0x$(python3 -c "import sys; print('20965255' + '0'*64 + hex($i)[2:].zfill(64))")\"},\"latest\"],\"id\":$i}"
done

# Phase 2: Sustained amplification — each request now triggers 1500-row DB batch
# Monitor DB with: SELECT count(*), query FROM pg_stat_activity GROUP BY query;
for i in $(seq 1 100); do
  curl -s -X POST http://localhost:8545 \
    -H 'Content-Type: application/json' \
    -d '{"jsonrpc":"2.0","method":"eth_call","params":[{"to":"CONTRACT_ADDR","data":"0x<sload_selector><nonexistent_slot>"},"latest"],"id":1}'
done
# Observe: each call generates SQL: SELECT slot, value FROM contract_state WHERE contract_id=X AND slot IN (<1500 slots>)
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L63-67)
```java
        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }
```

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```
