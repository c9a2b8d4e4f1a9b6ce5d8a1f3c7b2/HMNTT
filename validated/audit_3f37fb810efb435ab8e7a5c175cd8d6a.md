All technical claims in the report are verified against the actual code. Here is the audit result:

---

Audit Report

## Title
Perpetual Cache Miss on Non-Exchange-Rate System Files Due to Missing `roundDownToHour()` Normalization

## Summary
`SystemFileLoader.load()` applies `roundDownToHour()` only to exchange-rate and fee-schedule file IDs before constructing the `CacheKey`. All other system files (addressBook 101/102, throttleDefinitions, hapiPermissions) receive the raw nanosecond wall-clock timestamp from `getCurrentTimestamp()`, which is unique on every JVM call. This renders the `defaultSystemFileCacheManager` permanently ineffective for those files, causing one or more DB queries per request with no cache benefit.

## Finding Description

**`FileReadableKVState.readFromDataSource()`** always calls `getCurrentTimestamp()` and passes the result directly to `systemFileLoader.load()` for every system file lookup: [1](#0-0) 

`getCurrentTimestamp()` is defined as: [2](#0-1) 

This returns `Instant.now()` converted to nanoseconds — a value that is unique on every call.

Inside `SystemFileLoader.load()`, `roundDownToHour()` is applied **only** for the three exchange-rate/fee-schedule file IDs: [3](#0-2) 

For all other system files (addressBook 101/102, throttleDefinitions, hapiPermissions), `consensusTimestamp` remains the raw nanosecond value. The resulting `CacheKey(fileId, nanoTimestamp)` is always a new, unique key. The cache lookup at line 129 always misses, and `loadFromDB()` is called on every request: [4](#0-3) 

The `defaultSystemFileCacheManager` is backed by the `systemFile` cache spec (`expireAfterWrite=10m,maximumSize=20,recordStats`): [5](#0-4) [6](#0-5) 

With `maximumSize=20`, the cache fills with 20 unique-timestamp entries and then evicts them, never producing a hit.

**Root cause:** `roundDownToHour()` was applied only to the three exchange-rate/fee-schedule files. The remaining system files were not given any timestamp normalization, so their cache keys are always unique.

**Failed assumption:** The `defaultSystemFileCacheManager` was intended to absorb repeated reads of addressBook/throttleDefinitions/hapiPermissions. It cannot, because the cache key always contains a fresh nanosecond timestamp.

## Impact Explanation

Every contract-call request that causes the EVM to read a non-exchange-rate system file results in a `fileDataRepository.getFileAtTimestamp()` DB query with no cache benefit. The default rate limit is 500 requests/second: [7](#0-6) 

At 500 req/s sustained, this produces 500 uncached DB queries/second for system files alone. Additionally, `maxFileAttempts = 12` means each cache miss can trigger up to 12 DB queries in the retry loop if file data is corrupt or unparseable: [8](#0-7) [9](#0-8) 

This can sustain elevated DB CPU over extended periods with no brute-force required — the attacker simply sends requests at the permitted rate.

## Likelihood Explanation

**Preconditions:** None. No authentication, no privileged account, no special contract deployment required. Any caller of the public `/api/v1/contracts/call` endpoint can trigger this.

**Feasibility:** The attacker sends standard `eth_call` requests at the default 500 req/s rate limit. The rate limiter is a token bucket that refills at 500/s — it does not prevent the attack, it merely caps it at the designed maximum throughput: [10](#0-9) 

The attack is trivially repeatable from a single IP using any HTTP client.

## Recommendation

Apply the same timestamp normalization to all system files that are expected to be stable over time. For files like addressBook, throttleDefinitions, and hapiPermissions — which change infrequently — apply `roundDownToHour()` (or a similar coarser-grained normalization such as `roundDownToMinute()`) before constructing the `CacheKey`, mirroring the existing pattern used for exchange-rate and fee-schedule files:

```java
// In SystemFileLoader.load(), extend normalization to all system files:
consensusTimestamp = roundDownToHour(consensusTimestamp);
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

Alternatively, for files that never change during a running instance (e.g., addressBook), consider caching the result indefinitely in a simple `Map` field rather than using a time-keyed cache at all.

## Proof of Concept

1. Deploy or use an existing mirror node instance with default configuration.
2. Send repeated `POST /api/v1/contracts/call` requests at 500 req/s targeting any contract that causes the EVM to read `addressBook` (file 101/102), `throttleDefinitions`, or `hapiPermissions`.
3. Monitor `fileDataRepository.getFileAtTimestamp()` query rate in the DB.
4. Observe that the query rate matches the request rate (500/s) with zero cache hits, confirming the `defaultSystemFileCacheManager` is permanently ineffective for these files.

The cache miss can be confirmed by enabling `recordStats` (already configured by default) and observing a hit rate of 0% for the `systemFile` cache while the `fee` (exchange-rate) cache shows a high hit rate. [11](#0-10)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java (L54-57)
```java
        final var currentTimestamp = getCurrentTimestamp();

        if (systemFileLoader.isSystemFile(key)) {
            return systemFileLoader.load(key, currentTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/Utils.java (L57-60)
```java
    public static long getCurrentTimestamp() {
        final var now = Instant.now();
        return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L71-75)
```java
    @Getter(lazy = true, value = AccessLevel.PRIVATE)
    private final RetryTemplate retryTemplate = new RetryTemplate(RetryPolicy.builder()
            .maxRetries(properties.getMaxFileAttempts() - 1)
            .predicate(e -> e instanceof InvalidFileException)
            .build());
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L105-142)
```java
    public @Nullable File load(FileID fileId, long consensusTimestamp) {
        // Skip database for network properties so that CN props can't override MN props and cause us to break.
        if (genesisNetworkProperties.fileId().equals(fileId)) {
            return genesisNetworkProperties;
        }

        var cacheManager = defaultSystemFileCacheManager;

        if (fileId.equals(exchangeRateFileId)
                || fileId.equals(feeSchedulesFileId)
                || fileId.equals(simpleFeeSchedulesFileId)) {
            cacheManager = exchangeRatesCacheManager;
            consensusTimestamp = roundDownToHour(consensusTimestamp);
        }

        final var cacheKey = new CacheKey(fileId, consensusTimestamp);
        log.debug("Looking up {}", cacheKey);
        final var cache = cacheManager.getCache(CACHE_NAME);

        if (cache == null) {
            return loadFromDB(fileId, consensusTimestamp);
        }

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
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L44-45)
```java
    @NotBlank
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L137-143)
```java
    @Bean(CACHE_MANAGER_SYSTEM_FILE)
    CacheManager cacheManagerSystemFile() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getSystemFile());
        return caffeineCacheManager;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L34-35)
```java
    @Min(1)
    private long requestsPerSecond = 500;
```

**File:** docs/configuration.md (L707-707)
```markdown
| `hiero.mirror.web3.evm.maxFileAttempts`                      | 12                                                 | The maximum amount of times to query for Hedera files when the contents are not valid.                                                                                                           |
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
