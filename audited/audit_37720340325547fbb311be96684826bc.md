### Title
Thundering Herd / Cache Stampede in `SystemFileLoader.load()` Allows Unprivileged DB Amplification DoS

### Summary
The `load()` method in `SystemFileLoader` uses a non-atomic cache check-then-act pattern: it calls `cache.get()`, and if the result is null, calls `loadFromDB()` then `cache.put()`. There is no synchronization between these steps, so N concurrent threads hitting the same cache key simultaneously will all observe a miss and all independently execute `loadFromDB()` → `loadWithRetry()`, each capable of issuing up to 12 DB queries (the default `maxFileAttempts`). Any unauthenticated caller of the public JSON-RPC endpoint can trigger this.

### Finding Description

**Exact code path:**

`SystemFileLoader.java`, `load()` method, lines 128–141:

```java
// Try to return the value from the cache
var file = cache.get(cacheKey, File.class);   // line 129 – plain lookup, not atomic
if (file != null) {
    return file;
}

// The value was not in cache -> try to load from DB
var result = loadFromDB(fileId, consensusTimestamp);  // line 135 – all N threads reach here
if (result != null) {
    log.info("Updating cache for key {}", cacheKey);
    cache.put(cacheKey, result);                       // line 138 – N redundant puts
}
```

`loadFromDB()` (line 144) delegates to `loadWithRetry()` (line 166), which drives a `RetryTemplate` configured with `maxRetries = properties.getMaxFileAttempts() - 1`. The default value of `maxFileAttempts` is **12** (`EvmProperties.java` line 65), so each `loadFromDB()` invocation can issue up to **12** sequential DB queries.

**Root cause:** Spring's `Cache.get(key, type)` is a plain read with no compare-and-set semantics. The code does not use `Cache.get(key, Callable)` (which in Spring's Caffeine integration delegates to Caffeine's atomic `get(key, mappingFunction)` and serialises concurrent loaders for the same key). The gap between the null-check on line 130 and the `cache.put()` on line 138 is an unguarded critical section.

**Why the cache type matters:** Both cache managers (`CACHE_MANAGER_SYSTEM_FILE` and `CACHE_MANAGER_EXCHANGE_RATES_SYSTEM_FILE`) are `CaffeineCacheManager` instances configured via `setCacheSpecification()`. Caffeine's manual `get`/`put` API does **not** prevent concurrent computation; only `get(key, mappingFunction)` / `LoadingCache` provides that guarantee. Spring's `Cache.get(key, Callable)` wrapper would use the atomic path, but it is not used here.

**Exploit flow:**
1. Attacker identifies any system file endpoint reachable via public JSON-RPC (e.g. `eth_call`, `eth_estimateGas`). These calls internally trigger `SystemFileLoader.load()` for fee schedules, exchange rates, address books, or throttle definitions.
2. For exchange-rate / fee-schedule files the timestamp is rounded down to the hour (line 117), making the cache key identical for all requests within the same hour — maximising the window for a cold-cache burst.
3. Attacker sends N concurrent requests before the first response has populated the cache (e.g. immediately after the hour boundary, or after a cache eviction).
4. All N threads pass the `cache.get()` null-check simultaneously and each independently calls `loadFromDB()` → `loadWithRetry()`.
5. Each `loadWithRetry()` call issues up to 12 DB queries (default `maxFileAttempts = 12`).
6. Total DB queries = **N × 12** for a single burst.

### Impact Explanation
The DB amplification factor is `N × maxFileAttempts` (default N × 12). A modest burst of 100 concurrent requests produces up to 1 200 simultaneous DB queries for a single logical cache key. Because the system file cache is shared across all EVM execution paths, sustained bursts can exhaust the DB connection pool, causing latency spikes or outright failures for all users of the mirror-node web3 service. No authentication or special privilege is required; the JSON-RPC endpoints are public.

### Likelihood Explanation
The attack requires no credentials, no on-chain funds, and no special knowledge beyond knowing the service is running. The hour-boundary rounding for exchange-rate and fee-schedule files creates a predictable, recurring cold-cache window every 3 600 seconds. Standard HTTP load-testing tools (e.g. `wrk`, `ab`, `hey`) are sufficient to reproduce the condition. The attack is repeatable on demand.

### Recommendation
Replace the manual check-then-act pattern with Spring's atomic `Cache.get(key, Callable)` overload, which in the Caffeine backend serialises concurrent loaders for the same key:

```java
// Instead of:
var file = cache.get(cacheKey, File.class);
if (file != null) return file;
var result = loadFromDB(fileId, consensusTimestamp);
if (result != null) cache.put(cacheKey, result);
return result;

// Use:
return cache.get(cacheKey, File.class,
        () -> loadFromDB(fileId, consensusTimestamp));
```

This ensures only one thread executes `loadFromDB()` per cache key; all other concurrent threads block until the value is available and then read it from cache, eliminating the stampede entirely.

### Proof of Concept
1. Deploy or point at a mirror-node web3 instance with a cold cache (restart, or wait for the top of an hour for exchange-rate files).
2. Send 100 concurrent `eth_estimateGas` requests that require fee-schedule resolution at the current hour-rounded timestamp:
   ```bash
   hey -n 100 -c 100 -m POST \
     -H "Content-Type: application/json" \
     -d '{"jsonrpc":"2.0","method":"eth_estimateGas","params":[{"to":"0x...","data":"0x..."}],"id":1}' \
     http://<mirror-node>/api/v1/contracts/call
   ```
3. Observe DB query logs: up to 1 200 `getFileAtTimestamp` queries are issued within the same second for a single logical file/timestamp key, confirming the N × 12 amplification. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L113-118)
```java
        if (fileId.equals(exchangeRateFileId)
                || fileId.equals(feeSchedulesFileId)
                || fileId.equals(simpleFeeSchedulesFileId)) {
            cacheManager = exchangeRatesCacheManager;
            consensusTimestamp = roundDownToHour(consensusTimestamp);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L128-141)
```java
        // Try to return the value from the cache
        var file = cache.get(cacheKey, File.class);
        if (file != null) {
            return file;
        }

        // The value was not in cache -> try to load from DB
        var result = loadFromDB(fileId, consensusTimestamp);
        if (result != null) {
            log.info("Updating cache for key {}", cacheKey);
            cache.put(cacheKey, result);
        }

        return result;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L166-198)
```java
    private File loadWithRetry(final FileID key, final long currentTimestamp, SystemFile systemFile) {
        final var nanoSeconds = new AtomicLong(currentTimestamp);
        final var fileId = toEntityId(key).getId();
        final var attempt = new AtomicInteger(0);

        try {
            return getRetryTemplate().execute(() -> fileDataRepository
                    .getFileAtTimestamp(fileId, nanoSeconds.get())
                    .filter(fileData -> ArrayUtils.isNotEmpty(fileData.getFileData()))
                    .map(fileData -> {
                        try {
                            var bytes = Bytes.wrap(fileData.getFileData());
                            var codec = systemFile.codec;
                            if (codec != null) {
                                codec.parse(bytes.toReadableSequentialData());
                            }
                            return File.newBuilder().contents(bytes).fileId(key).build();
                        } catch (ParseException e) {
                            log.warn(
                                    "Failed to parse file data for fileId {} at {}, retry attempt {}. Exception: ",
                                    fileId,
                                    nanoSeconds.get(),
                                    attempt.incrementAndGet(),
                                    e);
                            nanoSeconds.set(fileData.getConsensusTimestamp() - 1);
                            throw new InvalidFileException(e);
                        }
                    })
                    .orElse(systemFile.genesisFile()));
        } catch (RetryException e) {
            return systemFile.genesisFile();
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/properties/EvmProperties.java (L64-65)
```java
    @Min(1)
    private int maxFileAttempts = 12;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L137-151)
```java
    @Bean(CACHE_MANAGER_SYSTEM_FILE)
    CacheManager cacheManagerSystemFile() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getSystemFile());
        return caffeineCacheManager;
    }

    @Bean(CACHE_MANAGER_EXCHANGE_RATES_SYSTEM_FILE)
    CacheManager cacheManagerSystemFileExchangeRates() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getFee());
        return caffeineCacheManager;
    }
```
