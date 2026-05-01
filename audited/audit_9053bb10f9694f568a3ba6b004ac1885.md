Looking at the actual call chain:

**`FileReadableKVState.readFromDataSource()`** (line 57) calls `systemFileLoader.load(key, currentTimestamp)` where `currentTimestamp = getCurrentTimestamp()` — the current wall-clock nanoseconds — **not** a user-supplied value.

**`SystemFileLoader.load()`** (lines 113-118) applies `roundDownToHour()` only for `exchangeRateFileId`, `feeSchedulesFileId`, and `simpleFeeSchedulesFileId`. Address book files 101/102 fall through to line 120 with the raw nanosecond timestamp as the `CacheKey`.

**`CacheKey`** is `record CacheKey(FileID fileId, long timestamp)` — unique per nanosecond.

The user does **not** supply the timestamp for address book files. The system generates it from wall-clock time. However, the cache thrashing effect is real and exploitable without any privilege.

---

### Title
Cache Key Timestamp Normalization Missing for Address Book Files Causes Perpetual Cache Thrashing and Sustained DB Load

### Summary
`SystemFileLoader.load()` applies `roundDownToHour()` timestamp normalization only for exchange rate, fee schedule, and simple fee schedule files, but not for address book files 101/102. Since `FileReadableKVState` passes the current wall-clock nanosecond timestamp as the cache key, every request creates a unique `CacheKey`, making the `defaultSystemFileCacheManager` (maximumSize=20, expireAfterWrite=10m) perpetually ineffective. An unprivileged attacker sending repeated requests forces every address book read to hit the database.

### Finding Description
In `FileReadableKVState.readFromDataSource()`:
```java
final var currentTimestamp = getCurrentTimestamp(); // wall-clock nanoseconds
if (systemFileLoader.isSystemFile(key)) {
    return systemFileLoader.load(key, currentTimestamp); // always unique
}
``` [1](#0-0) 

In `SystemFileLoader.load()`, the timestamp is rounded to the hour only for three specific file IDs:
```java
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp); // normalization applied
}
// address book 101/102: falls through with raw nanosecond timestamp
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
``` [2](#0-1) 

`CacheKey` is a record keyed on `(FileID, long timestamp)`: [3](#0-2) 

Since `getCurrentTimestamp()` returns nanosecond-precision wall-clock time, every request at a different nanosecond produces a distinct `CacheKey`. The cache (maximumSize=20) fills immediately and every subsequent request evicts an older entry and misses the cache, falling through to `loadFromDB()` → `fileDataRepository.getFileAtTimestamp()` on every call. [4](#0-3) 

The `defaultSystemFileCacheManager` is configured as `expireAfterWrite=10m,maximumSize=20`: [5](#0-4) 

### Impact Explanation
The cache for address book files 101/102 is structurally non-functional. Every request that triggers an address book read (e.g., any contract call that exercises the EVM's address book lookup) issues a DB query. At the default rate limit of 500 RPS, this is up to 500 uncached DB queries per second for address book data alone, sustained indefinitely. This degrades DB performance for all mirror node consumers and can cause query timeouts or connection pool exhaustion under sustained load. [6](#0-5) 

### Likelihood Explanation
No authentication or special privileges are required. Any client with access to the `/api/v1/contracts/call` endpoint can trigger address book reads by sending repeated contract call requests. The attacker does not need to control or supply the timestamp — the system's own use of nanosecond wall-clock time as the cache key guarantees a cache miss on every request. The attack is trivially repeatable with a simple HTTP loop.

### Recommendation
Apply the same `roundDownToHour()` (or a similar coarser granularity normalization, e.g., round to minute or second) to address book file timestamps before constructing the `CacheKey`, mirroring the treatment already applied to exchange rate and fee schedule files:

```java
// In SystemFileLoader.load(), extend normalization to address book files:
if (fileId.equals(addressBookFile101Id) || fileId.equals(addressBookFile102Id)
        || fileId.equals(exchangeRateFileId) || ...) {
    consensusTimestamp = roundDownToHour(consensusTimestamp);
}
```

Alternatively, since address book files change very infrequently, cache them by `fileId` alone (dropping the timestamp dimension entirely) with a bounded TTL.

### Proof of Concept
1. Deploy the mirror node web3 service with default configuration (`systemFile: expireAfterWrite=10m,maximumSize=20`).
2. Enable DB query logging.
3. Send 25+ rapid POST requests to `/api/v1/contracts/call` with any payload that causes the EVM to read the address book (e.g., a contract that calls a system precompile).
4. Observe in DB logs: every request issues a `SELECT` against `file_data` for entity IDs 101 and 102 — no cache hits occur.
5. Confirm: the Caffeine cache stats show 0 hits and N misses (one per request), because each request's `CacheKey` contains a distinct nanosecond timestamp.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L276-283)
```java
    private record CacheKey(FileID fileId, long timestamp) {

        @Override
        public String toString() {
            final var entityId = EntityId.of(fileId.shardNum(), fileId.realmNum(), fileId.fileNum());
            return "FileId=" + entityId + ", timestamp=" + Instant.ofEpochSecond(0L, timestamp);
        }
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
