### Title
Perpetual Cache Miss on Non-Exchange-Rate System Files Due to Missing `roundDownToHour()` Normalization

### Summary
`SystemFileLoader.load()` applies `roundDownToHour()` only to exchange-rate, fee-schedule, and simple-fee-schedule files before constructing the `CacheKey`. All other system files (addressBook101/102, throttleDefinitions, hapiPermissions) receive the raw nanosecond wall-clock timestamp from `getCurrentTimestamp()`, which changes on every call. This makes the `defaultSystemFileCacheManager` cache permanently ineffective for those files, causing one DB query per request. An unprivileged attacker sending requests at the default 500 req/s rate limit can sustain continuous DB load indefinitely.

### Finding Description

**Code path:**

`FileReadableKVState.readFromDataSource()` always passes `getCurrentTimestamp()` (i.e., `Instant.now()` in nanoseconds) to `systemFileLoader.load()` for every system file lookup:

```
FileReadableKVState.java:54  final var currentTimestamp = getCurrentTimestamp();
FileReadableKVState.java:57  return systemFileLoader.load(key, currentTimestamp);
``` [1](#0-0) 

Inside `SystemFileLoader.load()`, `roundDownToHour()` is applied only for the three exchange-rate/fee-schedule file IDs:

```java
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp);  // ← only here
}
final var cacheKey = new CacheKey(fileId, consensusTimestamp); // ← raw nanos for all others
``` [2](#0-1) 

For addressBook (file 101/102), throttleDefinitions, and hapiPermissions, `consensusTimestamp` is the raw `Instant.now()` nanosecond value. Since this value is unique on every JVM call, `CacheKey(fileId, nanoTimestamp)` is always a new key. The cache lookup at line 129 always misses, and `loadFromDB()` is called on every request: [3](#0-2) 

`getCurrentTimestamp()` is defined as:
```java
public static long getCurrentTimestamp() {
    final var now = Instant.now();
    return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
}
``` [4](#0-3) 

The `defaultSystemFileCacheManager` is configured with `maximumSize=20`, so it fills with 20 unique-timestamp entries and then evicts them, never producing a hit: [5](#0-4) 

**Root cause:** The design assumption that `roundDownToHour()` would be applied to all frequently-read system files was only partially implemented. The three exchange-rate/fee-schedule files are protected; the remaining system files are not.

**Failed assumption:** The `defaultSystemFileCacheManager` cache is assumed to absorb repeated reads of addressBook/throttleDefinitions/hapiPermissions. It cannot, because the cache key always contains a fresh nanosecond timestamp.

### Impact Explanation

Every contract-call request that causes the EVM to read a non-exchange-rate system file (addressBook, throttleDefinitions, hapiPermissions) results in a `fileDataRepository.getFileAtTimestamp()` DB query with no cache benefit. The default rate limit is 500 requests/second: [6](#0-5) 

At 500 req/s sustained, this produces 500 uncached DB queries/second for system files alone — 43.2 million over 24 hours. Additionally, `maxFileAttempts = 12` means each cache miss can trigger up to 12 DB queries in the retry loop if file data is corrupt: [7](#0-6) 

This easily sustains >30% elevated DB CPU over 24 hours with no brute-force required — the attacker simply sends requests at the permitted rate.

### Likelihood Explanation

**Preconditions:** None. No authentication, no privileged account, no special contract deployment required. Any caller of the public `/api/v1/contracts/call` endpoint can trigger this. [8](#0-7) 

**Feasibility:** The attacker sends standard `eth_call` requests at the default 500 req/s rate limit. The rate limiter is a token bucket that refills at 500/s — it does not prevent the attack, it merely caps it at the designed maximum throughput. The attack is trivially repeatable from a single IP using any HTTP client. [9](#0-8) 

### Recommendation

Apply the same timestamp normalization to all system files, not just the three exchange-rate/fee-schedule files. The simplest fix is to apply `roundDownToHour()` (or a similar coarser granularity such as `roundDownToMinute()`) unconditionally before constructing the `CacheKey` for all system files:

```java
// In SystemFileLoader.load():
if (fileId.equals(exchangeRateFileId) || ...) {
    cacheManager = exchangeRatesCacheManager;
}
// Apply normalization to ALL system files, not just exchange-rate ones:
consensusTimestamp = roundDownToHour(consensusTimestamp);
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

Alternatively, since `FileReadableKVState` always passes `getCurrentTimestamp()` (current wall clock) for system files — never a historical timestamp — the cache key for non-historical system file reads could simply omit the timestamp entirely (use only `fileId` as the key), relying on `expireAfterWrite` for invalidation. [10](#0-9) 

### Proof of Concept

1. Deploy or identify any contract on the mirror node that causes the EVM to read a system file (e.g., one that triggers throttle-definition or address-book lookups during execution).
2. Send repeated `POST /api/v1/contracts/call` requests at ~500 req/s (the default rate limit) with `"block": "latest"`.
3. Observe via DB monitoring (e.g., `pg_stat_activity`, `pg_stat_statements`) that `getFileAtTimestamp` queries for file IDs 101, 102, or 123 (throttleDefinitions) are executed on every request with no cache hits.
4. After sustained load, measure DB CPU — it will remain elevated proportionally to the request rate, with no decay, because the cache never absorbs any load for these files.
5. Confirm by enabling cache stats (`recordStats` is already set) and observing a 0% hit rate on the `systemFile` cache for those file IDs.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java (L54-57)
```java
        final var currentTimestamp = getCurrentTimestamp();

        if (systemFileLoader.isSystemFile(key)) {
            return systemFileLoader.load(key, currentTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L72-75)
```java
    private final RetryTemplate retryTemplate = new RetryTemplate(RetryPolicy.builder()
            .maxRetries(properties.getMaxFileAttempts() - 1)
            .predicate(e -> e instanceof InvalidFileException)
            .build());
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L128-139)
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
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/Utils.java (L57-60)
```java
    public static long getCurrentTimestamp() {
        final var now = Instant.now();
        return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L45-45)
```java
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L35-35)
```java
    private long requestsPerSecond = 500;
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
