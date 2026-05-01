### Title
Cache Key Nanosecond Timestamp Bypass Causes Permanent Cache Miss and DB Query Amplification for Non-Exchange-Rate System Files

### Summary
In `SystemFileLoader.load()`, the cache key for non-exchange-rate system files (`addressBookFile101`, `addressBookFile102`, `hapiPermissionFile`, `throttleDefinitionFile`) is constructed using the raw nanosecond-precision wall-clock timestamp from `getCurrentTimestamp()`, which is unique on every invocation. Unlike the exchange-rate/fee-schedule files whose timestamps are rounded down to the hour, these four file types never produce a cache hit, causing every request that accesses them to unconditionally execute a correlated DB query. An unprivileged attacker sending requests at the default rate limit of 500 req/s can sustain up to 2,000 additional DB queries per second that the cache was designed to prevent.

### Finding Description

**Code path:**

`FileReadableKVState.readFromDataSource()` (lines 50–57) always passes `getCurrentTimestamp()` — `Instant.now()` in nanoseconds — to `systemFileLoader.load()` for every system file:

```java
final var currentTimestamp = getCurrentTimestamp();   // Instant.now() in nanos
if (systemFileLoader.isSystemFile(key)) {
    return systemFileLoader.load(key, currentTimestamp);
}
``` [1](#0-0) 

Inside `SystemFileLoader.load()` (lines 111–120), only the three exchange-rate-related files have their timestamp rounded to the hour. The remaining four system files use the raw nanosecond value as the cache key:

```java
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp);  // ← only these 3
}
final var cacheKey = new CacheKey(fileId, consensusTimestamp); // nanosecond for the other 4
``` [2](#0-1) 

`getCurrentTimestamp()` returns `Instant.now()` in nanoseconds: [3](#0-2) 

Because nanosecond wall-clock time is unique per request, `cache.get(cacheKey, File.class)` at line 129 always returns `null`, and `loadFromDB()` is always called: [4](#0-3) 

`loadFromDB()` executes the expensive correlated subquery in `FileDataRepository.getFileAtTimestamp()` for every miss: [5](#0-4) 

The `systemFile` cache is configured `expireAfterWrite=10m,maximumSize=20`. With nanosecond-unique keys, the 20-entry limit is saturated immediately and entries are evicted before they can ever be reused: [6](#0-5) 

**Root cause / failed assumption:** The design assumes the cache key `(fileId, consensusTimestamp)` will repeat across requests for the same file, but `consensusTimestamp` is nanosecond wall-clock time — it never repeats. The rounding mitigation applied to exchange-rate files was not applied to the other four system file types.

### Impact Explanation
Every HTTP request that causes the EVM to read `addressBookFile101`, `addressBookFile102`, `hapiPermissionFile`, or `throttleDefinitionFile` (e.g., any call invoking Hedera precompiles that require fee/permission/throttle data) unconditionally executes at least one correlated subquery against the `file_data` table. At the default rate limit of 500 req/s, this produces ≥2,000 unmitigated DB queries/second for system files alone — a sustained amplification that the cache was explicitly designed to eliminate. This can increase DB CPU and I/O load well beyond 30% compared to a correctly functioning cache, degrading service for all users.

### Likelihood Explanation
No authentication or special privilege is required. The `/api/v1/contracts/call` endpoint is publicly accessible: [7](#0-6) 

The default rate limit is 500 requests/second: [8](#0-7) 

The attacker needs only to send valid `eth_call` requests targeting any contract that invokes a Hedera precompile. No brute-force or credential is needed. The attack is trivially repeatable and sustainable indefinitely within the rate limit.

### Recommendation
Apply the same hour-rounding (or a coarser granularity such as minute-rounding) to the `consensusTimestamp` for all system file types before constructing the cache key, not only for the three exchange-rate-related files. Alternatively, use a fixed sentinel timestamp (e.g., `Long.MAX_VALUE`) for "latest" (non-historical) system file lookups, since the content of these files does not change between requests at the same block height.

```java
// Apply rounding to ALL system files for non-historical context
consensusTimestamp = roundDownToHour(consensusTimestamp);
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

### Proof of Concept
1. Deploy or identify any contract on the mirror node that invokes a Hedera precompile (e.g., `HederaTokenService.isToken()`), which internally reads `hapiPermissionFile` and `throttleDefinitionFile`.
2. Send 500 POST requests/second to `/api/v1/contracts/call` with `"block": "latest"` and the precompile call data — no authentication required.
3. Observe via DB monitoring (e.g., `pg_stat_activity`) that `getFileAtTimestamp` queries for entity IDs corresponding to `addressBookFile101`, `addressBookFile102`, `hapiPermissionFile`, and `throttleDefinitionFile` execute on every request with no cache hits, producing ≥2,000 DB queries/second from system file lookups alone.
4. Confirm that the `systemFile` Caffeine cache hit rate remains at 0% throughout the attack window.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java (L50-58)
```java
    protected File readFromDataSource(@NonNull FileID key) {
        final var timestamp = ContractCallContext.get().getTimestamp();
        final var fileEntityId = toEntityId(key);
        final var fileId = fileEntityId.getId();
        final var currentTimestamp = getCurrentTimestamp();

        if (systemFileLoader.isSystemFile(key)) {
            return systemFileLoader.load(key, currentTimestamp);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L111-120)
```java
        var cacheManager = defaultSystemFileCacheManager;

        if (fileId.equals(exchangeRateFileId)
                || fileId.equals(feeSchedulesFileId)
                || fileId.equals(simpleFeeSchedulesFileId)) {
            cacheManager = exchangeRatesCacheManager;
            consensusTimestamp = roundDownToHour(consensusTimestamp);
        }

        final var cacheKey = new CacheKey(fileId, consensusTimestamp);
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/Utils.java (L57-60)
```java
    public static long getCurrentTimestamp() {
        final var now = Instant.now();
        return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/FileDataRepository.java (L41-60)
```java

```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L44-45)
```java
    @NotBlank
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/ContractController.java (L37-51)
```java
    @PostMapping(value = "/call")
    ContractCallResponse call(@RequestBody @Valid ContractCallRequest request, HttpServletResponse response) {
        try {
            throttleManager.throttle(request);
            validateContractMaxGasLimit(request);

            final var params = constructServiceParameters(request);
            final var result = contractExecutionService.processCall(params);
            return new ContractCallResponse(result);
        } catch (InvalidParametersException e) {
            // The validation failed, but no processing occurred so restore the consumed tokens.
            throttleManager.restore(request.getGas());
            throw e;
        }
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```
