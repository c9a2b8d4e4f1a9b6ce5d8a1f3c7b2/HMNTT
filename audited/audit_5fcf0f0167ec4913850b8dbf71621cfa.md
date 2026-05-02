### Title
Cache Exhaustion via Unbounded Historical Timestamp Inputs for Fee Schedule Files

### Summary
The `load(FileID, long)` method in `SystemFileLoader` uses a `(fileId, roundedTimestamp)` composite cache key for fee/exchange-rate files, routing them to the `exchangeRatesCacheManager` whose default capacity is only 20 entries (`maximumSize=20`). An unprivileged caller can supply timestamps from 21 or more distinct hour buckets, filling and continuously evicting the cache, forcing every subsequent legitimate request to fall back to a database query.

### Finding Description
**Exact code path:**

In `SystemFileLoader.load()` (lines 111–136), when the requested `fileId` matches `feeSchedulesFileId`, `exchangeRateFileId`, or `simpleFeeSchedulesFileId`, the timestamp is rounded down to the hour and used as part of the cache key:

```java
// lines 111-118
if (fileId.equals(exchangeRateFileId)
        || fileId.equals(feeSchedulesFileId)
        || fileId.equals(simpleFeeSchedulesFileId)) {
    cacheManager = exchangeRatesCacheManager;
    consensusTimestamp = roundDownToHour(consensusTimestamp);
}
final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

`roundDownToHour` (lines 268–270) is:
```java
return (consensusTimestampNanos / NANOS_PER_HOUR) * NANOS_PER_HOUR;
```

The `exchangeRatesCacheManager` is configured via `CacheProperties.fee` (line 36 of `CacheProperties.java`):
```
expireAfterWrite=60m,maximumSize=20,recordStats
```

All three file types share this single 20-entry cache. Each distinct hour bucket for each file type occupies one slot. An attacker who sends requests with timestamps drawn from 21 or more different hours (e.g., `0 * NANOS_PER_HOUR`, `1 * NANOS_PER_HOUR`, …, `20 * NANOS_PER_HOUR`) creates 21 distinct `CacheKey` values. Caffeine's eviction then continuously displaces legitimate entries, forcing every real request to call `loadFromDB()` → `fileDataRepository.getFileAtTimestamp()`.

**Why existing checks are insufficient:**
- `roundDownToHour()` reduces the key space from nanosecond granularity to hourly granularity, but does not bound the range of acceptable hours. Historical timestamps spanning years are accepted without validation.
- `maximumSize=20` is the only guard, and it is trivially exceeded.
- There is no rate-limiting, timestamp range validation, or minimum-timestamp check in `load()`.

### Impact Explanation
Every cache miss for a fee/exchange-rate file triggers a synchronous database query (`getFileAtTimestamp`). Under sustained cache-thrashing, all fee-schedule lookups for every EVM call hit the database. This increases DB connection pool pressure and query latency for all users of the web3 API. The system remains functionally correct (it falls back to DB), so there is no economic damage or fund loss, but legitimate users experience degraded response times proportional to the attack rate.

### Likelihood Explanation
Any user of the public `eth_call` or `eth_estimateGas` endpoints can specify an arbitrary historical block number, which maps to an arbitrary consensus timestamp. No special privilege, key, or on-chain asset is required. The attack requires only ~21 HTTP requests to exhaust the cache, and must be repeated roughly every 60 minutes (the TTL) to sustain the degradation. It is fully automatable and repeatable.

### Recommendation
1. **Bound the accepted timestamp range**: Reject or clamp `consensusTimestamp` values that fall outside a reasonable window (e.g., reject timestamps older than the current time minus some configurable maximum history depth).
2. **Increase cache capacity or add per-file-type sub-caches**: If historical queries are a supported use case, size the cache to accommodate the expected range of distinct hour buckets, or use separate caches per file type.
3. **Add rate limiting on historical block queries** at the API layer to limit how many distinct timestamps a single client can query per time window.

### Proof of Concept
```
# NANOS_PER_HOUR = 3_600_000_000_000
# Send 21 eth_call requests, each with a block number mapping to a different hour:
for i in 0..20:
    timestamp_nanos = i * 3_600_000_000_000
    block = blockNumberForTimestamp(timestamp_nanos)
    POST /api/v1/contracts/call  { "block": block, "data": "<fee-schedule-touching call>" }

# Cache now holds 20 entries (Caffeine evicted the first).
# Any subsequent legitimate request for a recently-used hour is a cache miss → DB query.
# Repeat every 60 minutes to maintain the degraded state.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L111-118)
```java
        if (fileId.equals(exchangeRateFileId)
                || fileId.equals(feeSchedulesFileId)
                || fileId.equals(simpleFeeSchedulesFileId)) {
            cacheManager = exchangeRatesCacheManager;
            consensusTimestamp = roundDownToHour(consensusTimestamp);
        }

        final var cacheKey = new CacheKey(fileId, consensusTimestamp);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/state/SystemFileLoader.java (L268-270)
```java
    private long roundDownToHour(long consensusTimestampNanos) {
        return (consensusTimestampNanos / NANOS_PER_HOUR) * NANOS_PER_HOUR;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/properties/CacheProperties.java (L36-36)
```java
    private String fee = "expireAfterWrite=60m,maximumSize=20,recordStats";
```

**File:** web3/src/main/java/org/hiero/mirror/web3/evm/config/EvmConfiguration.java (L145-151)
```java
    @Bean(CACHE_MANAGER_EXCHANGE_RATES_SYSTEM_FILE)
    CacheManager cacheManagerSystemFileExchangeRates() {
        final CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification(cacheProperties.getFee());
        return caffeineCacheManager;
    }
```
