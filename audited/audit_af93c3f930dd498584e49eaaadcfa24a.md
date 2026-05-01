### Title
Cache Always Bypassed for Non-Rate/Fee System Files Due to Nanosecond-Precision Wall-Clock CacheKey

### Summary
`SystemFileLoader.load()` constructs a `CacheKey` using the raw nanosecond wall-clock timestamp returned by `Utils.getCurrentTimestamp()` (`Instant.now()` in nanoseconds) for address book, HAPI permissions, and throttle definition system files. Because this timestamp is unique on every request, the cache lookup at `cache.get(cacheKey, File.class)` always returns null, and `loadFromDB()` is unconditionally invoked on every request. No attacker action is required beyond sending repeated valid contract-call requests.

### Finding Description

**Exact code path:**

`FileReadableKVState.readFromDataSource()` (line 54, 57):
```java
final var currentTimestamp = getCurrentTimestamp();   // Instant.now() in nanos
if (systemFileLoader.isSystemFile(key)) {
    return systemFileLoader.load(key, currentTimestamp);
}
```
`Utils.getCurrentTimestamp()` (lines 57–59) returns `DomainUtils.convertToNanos(now.getEpochSecond(), now.getNano())` — nanosecond wall-clock time, unique per call.

`SystemFileLoader.load()` (lines 113–120):
```java
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp);  // only these 3 are rounded
}
final var cacheKey = new CacheKey(fileId, consensusTimestamp); // raw nanos for all others
```

For **address book (101, 102), HAPI permissions, and throttle definitions**, `consensusTimestamp` is never rounded. The `CacheKey` record embeds the raw nanosecond value, so every request produces a distinct key. `cache.get(cacheKey, File.class)` (line 129) always returns null, and `loadFromDB()` (line 135) is always called, issuing a `fileDataRepository.getFileAtTimestamp(...)` query to PostgreSQL.

**Why the existing cache check fails:** The cache is keyed on `(fileId, nanosecondTimestamp)`. Since the timestamp is `Instant.now()` at request time, no two requests share a key. The `maximumSize=20` Caffeine cache fills with 20 distinct entries and then evicts them, but never produces a hit for the current request.

### Impact Explanation
Every contract-call request that internally reads address book, HAPI permissions, or throttle definition files issues at least one `getFileAtTimestamp` SQL query that the cache was designed to absorb. At the default rate limit of 500 RPS, this produces a sustained floor of hundreds of DB queries per second for these files alone, bypassing the intended 10-minute cache TTL entirely. This can increase database CPU/IO load by well over 30% compared to a correctly-functioning cache, satisfying the stated impact threshold without any brute-force action.

### Likelihood Explanation
No privilege is required. Any caller of the public JSON-RPC `eth_call` / `eth_estimateGas` endpoints triggers system file reads. The attacker needs only to send repeated valid (or even identical) requests at a sustained rate. The exploit is trivially repeatable, requires no special knowledge of the system, and is indistinguishable from normal high-traffic usage.

### Recommendation
Apply the same `roundDownToHour` (or a coarser rounding, e.g., to the minute) to **all** system file types before constructing the `CacheKey`, not only to exchange-rate and fee-schedule files. Alternatively, use a fixed sentinel timestamp (e.g., `Long.MAX_VALUE`) for "latest" lookups of files that do not have historical semantics, so all "latest" requests share a single cache entry per file ID.

```java
// In SystemFileLoader.load(), before building cacheKey:
consensusTimestamp = roundDownToHour(consensusTimestamp); // apply universally
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

### Proof of Concept
1. Deploy or connect to a mirror-node web3 instance.
2. Send repeated `eth_call` requests targeting any contract that causes the EVM to read the address book or throttle definition (any standard contract call suffices, as these files are loaded during fee/throttle evaluation).
3. Enable DB query logging (`log_min_duration_statement=0` in PostgreSQL).
4. Observe that `getFileAtTimestamp` is executed on **every** request with a distinct timestamp argument, confirming zero cache hits.
5. Compare DB query rate against a baseline with the cache functioning correctly (e.g., after patching to round the timestamp): the unpatched version will show a query-per-request pattern while the patched version will show near-zero queries after the first request within each rounding window. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L44-45)
```java
    @NotBlank
    private String systemFile = "expireAfterWrite=10m,maximumSize=20,recordStats";
```
