Based on my code review, the claim is technically accurate. Here is my assessment:

**Confirmed facts from the code:**

1. `Utils.getCurrentTimestamp()` returns `DomainUtils.convertToNanos(Instant.now().getEpochSecond(), Instant.now().getNano())` — a unique nanosecond wall-clock value on every call. [1](#0-0) 

2. `FileReadableKVState.readFromDataSource()` always passes this value to `systemFileLoader.load()` for system files, ignoring any historical `ContractCallContext` timestamp. [2](#0-1) 

3. `SystemFileLoader.load()` only applies `roundDownToHour()` for the three rate/fee files. For address book (101, 102), HAPI permissions, and throttle definitions, the raw nanosecond value is embedded directly in `CacheKey`. [3](#0-2) 

4. The `defaultSystemFileCacheManager` (`CACHE_MANAGER_SYSTEM_FILE`) is configured as `expireAfterWrite=10m,maximumSize=20` — a 10-minute TTL that is never reached because no key is ever reused. [4](#0-3) 

---

Audit Report

## Title
Cache Always Bypassed for Non-Rate/Fee System Files Due to Nanosecond Wall-Clock CacheKey

## Summary
`SystemFileLoader.load()` constructs a `CacheKey` using the raw nanosecond wall-clock timestamp from `Utils.getCurrentTimestamp()` for address book (files 101/102), HAPI permissions, and throttle definition system files. Because this timestamp is unique on every request, the cache lookup always misses and `loadFromDB()` is unconditionally invoked, issuing a `fileDataRepository.getFileAtTimestamp(...)` SQL query to PostgreSQL on every call.

## Finding Description
`FileReadableKVState.readFromDataSource()` calls `getCurrentTimestamp()` (which returns `DomainUtils.convertToNanos(Instant.now().getEpochSecond(), Instant.now().getNano())`) and passes it directly to `systemFileLoader.load(key, currentTimestamp)` for all system files.

Inside `SystemFileLoader.load()`, only the three rate/fee files (`exchangeRateFileId`, `feeSchedulesFileId`, `simpleFeeSchedulesFileId`) have their timestamp rounded down to the hour boundary via `roundDownToHour()`. All other system files — address book 101, address book 102, HAPI permissions, and throttle definitions — use the raw nanosecond value as the second field of `CacheKey(fileId, consensusTimestamp)`.

Since `Instant.now()` returns a different value on every invocation, no two requests for these files share a `CacheKey`. The Caffeine cache (`expireAfterWrite=10m,maximumSize=20`) fills with 20 distinct entries and evicts them, but never produces a hit for any current request. The `cache.get(cacheKey, File.class)` call at line 129 always returns `null`, and `loadFromDB()` at line 135 is always executed.

**Affected files and lines:**
- `web3/src/main/java/org/hiero/mirror/web3/state/Utils.java`, lines 57–60
- `web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java`, lines 54–57
- `web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java`, lines 113–120, 129, 135
- `web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java`, line 45

## Impact Explanation
Every `eth_call` / `eth_estimateGas` request that internally reads address book, HAPI permissions, or throttle definition files issues at least one `getFileAtTimestamp` SQL query that the cache was designed to absorb. The intended 10-minute TTL is completely ineffective. At the default rate limit of 500 RPS (`hiero.mirror.web3.throttle.requestsPerSecond=500`), this produces a sustained floor of hundreds of additional DB queries per second for these files alone, increasing database CPU/IO load well beyond the intended baseline.

## Likelihood Explanation
No privilege is required. Any caller of the public JSON-RPC `eth_call` or `eth_estimateGas` endpoints triggers system file reads. Repeated valid (or even identical) requests at a sustained rate are sufficient. The condition is indistinguishable from normal high-traffic usage and requires no special knowledge of the system internals.

## Recommendation
Apply the same `roundDownToHour()` (or an equivalent coarser rounding, e.g., round-down-to-minute) to the `consensusTimestamp` for all system files before constructing the `CacheKey`, not only for the three rate/fee files. Alternatively, use a fixed sentinel value (e.g., `0L` or the most-recently-seen consensus timestamp from the DB) as the cache key for files that do not change frequently, so that repeated requests within the TTL window share a key and produce cache hits.

## Proof of Concept
1. Send any repeated `eth_call` request that causes the EVM to read the address book or throttle definitions (e.g., any contract call that triggers fee/throttle checks).
2. Enable `DEBUG` logging for `SystemFileLoader` — observe `"Looking up FileId=0.0.101, timestamp=<unique-nanos>"` logged with a different timestamp on every request.
3. Enable `INFO` logging — observe `"Updating cache for key ..."` logged on every request (never a cache hit).
4. Monitor PostgreSQL query logs — `getFileAtTimestamp` for entity IDs 101, 102, 111/121/122/123 will appear on every request with no cache-hit suppression.

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/Utils.java (L57-60)
```java
    public static long getCurrentTimestamp() {
        final var now = Instant.now();
        return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java (L54-57)
```java
        final var currentTimestamp = getCurrentTimestamp();

        if (systemFileLoader.isSystemFile(key)) {
            return systemFileLoader.load(key, currentTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L113-120)
```java
        if (fileId.equals(exchangeRateFileId)
                || fileId.equals(feeSchedulesFileId)
                || fileId.equals(simpleFeeSchedulesFileId)) {
            cacheManager = exchangeRatesCacheManager;
            consensusTimestamp = roundDownToHour(consensusTimestamp);
        }

        final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L44-45)
```java
    @NotBlank
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";
```
