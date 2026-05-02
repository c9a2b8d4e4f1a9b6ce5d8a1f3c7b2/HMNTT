### Title
Cache Stampede on `contractState` Cache Expiry Enables Unprivileged DB Amplification Attack

### Summary
The `contractState` Caffeine cache is configured with a 2-second `expireAfterWrite` TTL and no stampede protection. When the cache expires, all concurrent `eth_call` requests that arrive within the same window simultaneously miss the cache and each independently issue a database batch query — up to the full 500 req/s rate limit — multiplying DB load by the number of concurrent misses. No authentication or privilege is required.

### Finding Description

**Cache configuration** — `EvmConfiguration.cacheManagerContractState()` (lines 83–89) delegates to `CacheProperties.getContractState()` which hardcodes `expireAfterWrite=2s,maximumSize=25000,recordStats`. No `refreshAfterWrite` or `CacheLoader` is configured, so Caffeine provides zero stampede protection on expiry. [1](#0-0) [2](#0-1) 

**Unprotected miss path** — `ContractStateServiceImpl.findStorage()` (lines 63–69) calls `contractStateCache.get(key, byte[].class)`, which is Spring Cache's simple non-loading `get`. This returns `null` on a miss with no per-key locking. Every thread that calls this simultaneously after expiry gets `null` and independently proceeds to `findStorageBatch()`. [3](#0-2) 

**DB amplification in `findStorageBatch`** — Each concurrent miss calls `contractStateRepository.findStorageBatch(contractId.getId(), cachedSlots)` (line 103), where `cachedSlots` contains **all previously accessed slot keys for that contract** (up to 1500 slots, 5-minute TTL). Every concurrent miss issues this full batch query independently. [4](#0-3) 

**Why the throttle does not prevent this** — The rate limiter (`rateLimitBucket`, 500 req/s default) is a global token-bucket with no per-key or per-slot awareness. It permits up to 500 concurrent requests per second, all of which can legally target the same contract slot. The gas throttle is also ineffective: `scaleGas(21000)` returns `2` tokens, and the gas bucket capacity is `scaleGas(7_500_000_000) = 750_000` tokens, so 375,000 minimum-gas requests per second are permitted before the gas limit is hit — far above the 500 req/s RPS cap. [5](#0-4) [6](#0-5) 

**Root cause**: The cache miss path in `ContractStateServiceImpl.findStorage()` uses a read-then-act pattern (`get` → `null` → `findStorageBatch`) with no synchronization, while the cache TTL of 2 seconds is short enough to be reliably triggered by a sustained request stream.

### Impact Explanation

In steady state with a warm cache, a hot contract slot generates ~1 DB batch query per 2-second window. Under a stampede, up to 500 concurrent threads each issue a `findStorageBatch` query covering all cached slots for that contract. If a contract has 1500 cached slots, each stampede event sends 500 queries each scanning 1500 slots — a 500× amplification in query count and a proportionally larger amplification in rows scanned. This repeats every 2 seconds indefinitely. The DB connection pool can be exhausted, causing cascading latency or outright failures for all users of the mirror node. This directly satisfies the ≥30% resource consumption increase threshold with a single attacker using only the public API.

### Likelihood Explanation

No account, API key, or privileged access is required — only the ability to send HTTP POST requests to `/api/v1/contracts/call`. The attack is trivially scriptable: send 500 concurrent requests per second targeting the same `to` address and `data` selector. The 2-second TTL makes the stampede window reliably reproducible every 2 seconds. Any public mirror node endpoint is vulnerable. The attack is repeatable, low-cost, and requires no knowledge of internal state beyond a valid contract address.

### Recommendation

1. **Replace `expireAfterWrite` with `refreshAfterWrite` + `CacheLoader`**: Configure the Caffeine cache with a `CacheLoader` so that on expiry only one thread reloads while others receive the stale value. This is the canonical Caffeine stampede fix.
2. **Alternatively, use `Cache.get(key, valueLoader)` (loading variant)**: Replace `contractStateCache.get(key, byte[].class)` with `contractStateCache.get(key, () -> loadFromDb(...))`. Caffeine's loading `get` serializes concurrent loads for the same key — only one thread executes the loader, others block and receive the same result.
3. **Increase the TTL**: A 2-second TTL is extremely aggressive for contract state that changes at block cadence (~3–5 seconds). Raising it to 5–10 seconds reduces stampede frequency.
4. **Add per-key request coalescing**: Use a `ConcurrentHashMap<CacheKey, CompletableFuture<byte[]>>` to deduplicate in-flight DB requests for the same key.

### Proof of Concept

```python
import asyncio, aiohttp, time

TARGET = "http://<mirror-node>/api/v1/contracts/call"
PAYLOAD = {
    "to": "0x<contract_address>",
    "data": "0x<selector_reading_hot_slot>",
    "gas": 300000,
    "estimate": False,
    "block": "latest"
}

async def send(session):
    async with session.post(TARGET, json=PAYLOAD) as r:
        return r.status

async def stampede():
    # Wait for cache to warm, then flood just after 2s TTL boundary
    await asyncio.sleep(2.05)  # just past expiry
    async with aiohttp.ClientSession() as session:
        # Fire 500 concurrent requests simultaneously
        results = await asyncio.gather(*[send(session) for _ in range(500)])
    print(f"Responses: {set(results)}")

# Repeat every 2 seconds to sustain the attack
async def main():
    while True:
        await stampede()
        await asyncio.sleep(0.0)  # immediately re-trigger next window

asyncio.run(main())
```

**Expected result**: DB query rate spikes from ~1 batch query per 2 seconds to ~500 batch queries per 2 seconds for the targeted contract, each scanning all cached slots. Monitor with `pg_stat_activity` or DB slow-query logs to confirm simultaneous identical queries from all connection pool threads.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L83-89)
```java
    @Bean(CACHE_MANAGER_CONTRACT_STATE)
    CacheManager cacheManagerContractState() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getContractState());
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L27-28)
```java
    @NotBlank
    private String contractState = "expireAfterWrite=2s,maximumSize=25000,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L63-69)
```java
        final var cachedValue = contractStateCache.get(generateCacheKey(contractId, key), byte[].class);

        if (cachedValue != null && cachedValue != EMPTY_VALUE) {
            return Optional.of(cachedValue);
        }

        return findStorageBatch(contractId, key);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/service/ContractStateServiceImpl.java (L91-103)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L26-46)
```java
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;

    // Necessary since bucket4j has a max capacity and fill rate of 1 token per nanosecond
    public long getGasPerSecond() {
        return scaleGas(gasPerSecond);
    }

    public long scaleGas(long gas) {
        if (gas <= GAS_SCALE_FACTOR) {
            return 0L;
        }
        return Math.floorDiv(gas, GAS_SCALE_FACTOR);
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
