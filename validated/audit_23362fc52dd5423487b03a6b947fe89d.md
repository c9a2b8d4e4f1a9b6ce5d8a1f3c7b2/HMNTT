Based on my direct inspection of the source code, all technical claims in this report are accurate and verifiable.

**Verified facts:**

1. `FileReadableKVState.readFromDataSource()` at line 57 passes `getCurrentTimestamp()` (nanosecond wall-clock) to `systemFileLoader.load()` for all system files. [1](#0-0) 

2. `Utils.getCurrentTimestamp()` returns `Instant.now()` converted to nanoseconds — a unique value on every call. [2](#0-1) 

3. `SystemFileLoader.load()` applies `roundDownToHour()` only for `exchangeRateFileId`, `feeSchedulesFileId`, and `simpleFeeSchedulesFileId`. Address book files 101/102 fall through to line 120 with the raw nanosecond timestamp. [3](#0-2) 

4. `CacheKey` is a record keyed on `(FileID fileId, long timestamp)` — unique per nanosecond. [4](#0-3) 

5. The `defaultSystemFileCacheManager` is used for address book files (and other non-exchange-rate system files) without any timestamp normalization. [5](#0-4) 

All line references, call chains, and behavioral claims check out. The finding is technically sound.

---

# Audit Report

## Title
Cache Key Timestamp Normalization Missing for Address Book Files Causes Perpetual Cache Thrashing and Sustained DB Load

## Summary
`SystemFileLoader.load()` applies `roundDownToHour()` timestamp normalization only for exchange rate, fee schedule, and simple fee schedule files. Address book files 101/102 (and other system files using `defaultSystemFileCacheManager`) receive the raw nanosecond wall-clock timestamp as the cache key. Since `getCurrentTimestamp()` returns a unique nanosecond value on every call, every request produces a distinct `CacheKey`, rendering the cache permanently ineffective. Every address book read falls through to `loadFromDB()` → `fileDataRepository.getFileAtTimestamp()`.

## Finding Description
In `FileReadableKVState.readFromDataSource()`, the current wall-clock nanosecond timestamp is passed unconditionally to `systemFileLoader.load()` for all system files:

```java
// FileReadableKVState.java, lines 54–57
final var currentTimestamp = getCurrentTimestamp(); // Instant.now() in nanoseconds
if (systemFileLoader.isSystemFile(key)) {
    return systemFileLoader.load(key, currentTimestamp);
}
``` [6](#0-5) 

In `SystemFileLoader.load()`, timestamp normalization is applied only for three specific file IDs:

```java
// SystemFileLoader.java, lines 113–120
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp); // normalization applied
}
// address book 101/102: falls through with raw nanosecond timestamp
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
``` [3](#0-2) 

`CacheKey` is a record with equality based on both `fileId` and `timestamp`: [4](#0-3) 

`getCurrentTimestamp()` returns `Instant.now()` converted to nanoseconds, guaranteeing a unique value on every invocation: [2](#0-1) 

The `defaultSystemFileCacheManager` (used for address book files) is therefore structurally non-functional: every request inserts a new entry, the cache fills to `maximumSize=20` immediately, and every subsequent request is a cache miss that evicts an older entry and calls `loadFromDB()`. [7](#0-6) 

## Impact Explanation
The cache for address book files 101/102 never serves a hit. Every request that triggers an address book read issues a synchronous `fileDataRepository.getFileAtTimestamp()` DB query. Under sustained request load, this produces a proportional number of uncached DB queries for static data that should be cached. This degrades DB performance for all mirror node consumers and can cause query timeouts or connection pool exhaustion under sustained load.

## Likelihood Explanation
No authentication or special privileges are required. The attacker does not supply or control the timestamp — the system's own use of nanosecond wall-clock time as the cache key guarantees a cache miss on every request regardless of what the attacker does. Any client with access to endpoints that trigger address book reads (e.g., `/api/v1/contracts/call`) can sustain this load with a simple HTTP loop.

## Recommendation
Apply the same timestamp normalization to address book files (and all other files using `defaultSystemFileCacheManager`) as is already applied to exchange rate and fee schedule files. Since address book data changes infrequently, rounding down to the hour (or a longer interval) is appropriate:

```java
// In SystemFileLoader.load(), extend normalization to all cached system files:
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
} else {
    cacheManager = defaultSystemFileCacheManager;
}
consensusTimestamp = roundDownToHour(consensusTimestamp); // apply to all
```

Alternatively, apply normalization unconditionally before the branch, since all system files in this path are static or near-static data. [8](#0-7) 

## Proof of Concept
```
# Send repeated contract calls that trigger address book reads
for i in $(seq 1 1000); do
  curl -s -X POST http://<mirror-node>/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{"data":"<address-book-reading-calldata>","to":"<contract>"}' &
done
```

Each request calls `FileReadableKVState.readFromDataSource()` → `getCurrentTimestamp()` (unique nanosecond) → `SystemFileLoader.load()` → cache miss (unique `CacheKey`) → `loadFromDB()` → `fileDataRepository.getFileAtTimestamp()`. Monitoring the DB will show one query per request with no cache hits for file IDs 101/102. [9](#0-8)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/keyvalue/FileReadableKVState.java (L54-58)
```java
        final var currentTimestamp = getCurrentTimestamp();

        if (systemFileLoader.isSystemFile(key)) {
            return systemFileLoader.load(key, currentTimestamp);
        }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/Utils.java (L57-60)
```java
    public static long getCurrentTimestamp() {
        final var now = Instant.now();
        return DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano());
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L111-122)
```java
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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L144-151)
```java
    private @Nullable File loadFromDB(FileID fileId, long consensusTimestamp) {
        var systemFile = getSystemFiles().get(fileId);
        if (systemFile == null) {
            return null;
        }

        return loadWithRetry(fileId, consensusTimestamp, systemFile);
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L276-276)
```java
    private record CacheKey(FileID fileId, long timestamp) {
```
