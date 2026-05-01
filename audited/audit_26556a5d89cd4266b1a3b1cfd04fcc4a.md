### Title
Unauthenticated End-of-Month `maxTimestamp` Manipulation Doubles `account_balance` Scan Window in `getSupply()`

### Summary
An unprivileged external user can supply a `maxTimestamp` at the last nanosecond of any calendar month to the public `/api/v1/network/supply` endpoint. Because `getFirstDayOfMonth(maxTimestamp, -1)` always anchors the lower bound to the first day of the *previous* month, an end-of-month timestamp produces a ~60-day scan window versus the ~30-day window produced by a start-of-month timestamp — a 2× increase in rows scanned in `getSupplyHistory()`. No authentication, rate limiting, or window-size cap exists to prevent repeated exploitation.

### Finding Description

**Code path:**

`NetworkController.getSupply()` → `NetworkServiceImpl.getSupply(Bound)` → `AccountBalanceRepository.getSupplyHistory()`

**Root cause — lines 77–81 of `NetworkServiceImpl.java`:**

```java
final var optimalLowerBound = getFirstDayOfMonth(maxTimestamp, -1);  // line 77
minTimestamp = Math.max(minTimestamp, optimalLowerBound);             // line 78

networkSupply =
    accountBalanceRepository.getSupplyHistory(lowerBounds, upperBounds, minTimestamp, maxTimestamp); // line 80-81
```

`getFirstDayOfMonth(maxTimestamp, -1)` (lines 91–97) converts the nanosecond timestamp to a UTC `ZonedDateTime`, applies `plusMonths(-1)`, then snaps to `withDayOfMonth(1)` at midnight. The result is always the **first instant of the month preceding `maxTimestamp`'s month**, regardless of where within the month `maxTimestamp` falls.

When the attacker omits a lower bound, `timestamp.getAdjustedLowerRangeValue()` returns `0` (line 86–89 of `Bound.java`). `Math.max(0, optimalLowerBound)` always resolves to `optimalLowerBound`, so the effective scan window is:

| `maxTimestamp` position | `optimalLowerBound` | Window size |
|---|---|---|
| March 1 00:00:00.000000001 | Feb 1 00:00:00 | ~29 days |
| March 31 23:59:59.999999999 | Feb 1 00:00:00 | ~59 days |
| January 31 23:59:59.999999999 | Dec 1 00:00:00 | ~62 days |

The SQL query in `AccountBalanceRepository.getSupplyHistory` (lines 12–28) performs a full range scan:

```sql
where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp
```

with `distinct on (ab.account_id) … order by ab.account_id asc, ab.consensus_timestamp desc` — no `LIMIT`. Every row in the `account_balance` table within the timestamp window, for the configured unreleased-supply account ranges (7 ranges, accounts 2–750), is read and sorted.

**Why existing checks fail:**

- Line 73–75: only validates `minTimestamp <= maxTimestamp` — does not cap the window size.
- `@Size(max = 2)` on the controller parameter (line 134 of `NetworkController.java`) limits the *number* of timestamp parameters, not their values.
- No rate limiting, no response caching, and no query timeout are visible anywhere in the service or repository layer.
- The `Bound.of()` method (lines 169–182 of `Bound.java`) accepts any valid nanosecond value without range restriction.

### Impact Explanation

The `account_balance` table is partitioned by month. An end-of-month `maxTimestamp` forces a cross-partition scan spanning two full monthly partitions (~2× the I/O of a single-partition scan). With 7 account ranges and potentially millions of balance snapshot rows per month, the DB must read, sort, and aggregate 2× the data compared to a start-of-month timestamp. Sustained requests at this pattern from a single unauthenticated client can increase DB I/O well above the 30% threshold, degrading service for all users of the mirror node REST API.

### Likelihood Explanation

The endpoint is fully public and unauthenticated. The exploit requires only a single crafted HTTP GET request with a known-format timestamp parameter. The attacker needs no credentials, no internal access, and no special tooling — only knowledge of the API (publicly documented). The attack is trivially repeatable in a loop and is deterministic: any timestamp of the form `lte:YYYY-MM-LAST_DAY_OF_MONTH.999999999` reliably triggers the maximum window. The attacker can target months with 31 days (January, March, May, July, August, October, December) to maximize the window to ~62 days.

### Recommendation

1. **Cap the scan window**: After computing `optimalLowerBound`, enforce a maximum window size (e.g., 31 days) relative to `maxTimestamp`:
   ```java
   final long windowCap = maxTimestamp - 31L * 24 * 60 * 60 * DomainUtils.NANOS_PER_SECOND;
   minTimestamp = Math.max(minTimestamp, Math.max(optimalLowerBound, windowCap));
   ```
2. **Add rate limiting** on the `/api/v1/network/supply` endpoint per client IP.
3. **Add response caching** (e.g., short TTL cache keyed on the effective `[minTimestamp, maxTimestamp]` pair) to prevent repeated identical scans.
4. **Add a DB statement timeout** for this query to bound worst-case execution time.

### Proof of Concept

**Preconditions:** Public access to the mirror node REST API. No credentials required.

**Step 1 — Baseline request (start of month):**
```
GET /api/v1/network/supply?timestamp=lte:1740787200000000001
# 2025-03-01 00:00:00.000000001 UTC
# optimalLowerBound = 2025-02-01 00:00:00 UTC
# Scan window: ~28 days
```

**Step 2 — Attack request (end of month, maximum window):**
```
GET /api/v1/network/supply?timestamp=lte:1743379199999999999
# 2025-03-31 23:59:59.999999999 UTC
# optimalLowerBound = 2025-02-01 00:00:00 UTC
# Scan window: ~59 days (2.1× baseline)
```

**Step 3 — Repeat Step 2 in a loop** (e.g., 10 req/s). Monitor PostgreSQL `pg_stat_user_tables` for `account_balance` — `seq_scan`, `n_tup_read`, and `blks_read` will increase proportionally to the window size difference, exceeding 30% above the Step 1 baseline.

**Expected result:** DB I/O for `account_balance` approximately doubles compared to the start-of-month baseline, with no server-side rejection or throttling. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L77-81)
```java
            final var optimalLowerBound = getFirstDayOfMonth(maxTimestamp, -1);
            minTimestamp = Math.max(minTimestamp, optimalLowerBound);

            networkSupply =
                    accountBalanceRepository.getSupplyHistory(lowerBounds, upperBounds, minTimestamp, maxTimestamp);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L91-97)
```java
    private long getFirstDayOfMonth(long timestamp, int monthOffset) {
        final var instant = Instant.ofEpochSecond(0, timestamp);
        final var dateTime = instant.atZone(ZoneOffset.UTC);
        final var firstDay = dateTime.plusMonths(monthOffset).withDayOfMonth(1);

        return firstDay.toLocalDate().atStartOfDay(ZoneOffset.UTC).toEpochSecond() * DomainUtils.NANOS_PER_SECOND;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/AccountBalanceRepository.java (L12-28)
```java
    @Query(value = """
    with account_balances as (
      select distinct on (ab.account_id) ab.balance, ab.consensus_timestamp
      from account_balance ab
      join unnest(
            cast(string_to_array(:lowerBounds, ',') as bigint[]),
            cast(string_to_array(:upperBounds, ',') as bigint[])
         ) as ranges(min_val, max_val)
      on ab.account_id between ranges.min_val and ranges.max_val
      where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp
      order by ab.account_id asc, ab.consensus_timestamp desc
    )
    select cast(coalesce(sum(balance), 0) as bigint) as unreleased_supply,
           coalesce(max(consensus_timestamp), 0) as consensus_timestamp
    from account_balances
    """, nativeQuery = true)
    NetworkSupply getSupplyHistory(String lowerBounds, String upperBounds, long lowerTimestamp, long upperTimestamp);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L86-89)
```java
    public long getAdjustedLowerRangeValue() {
        if (this.lower == null) {
            return 0;
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L132-137)
```java
    @GetMapping("/supply")
    ResponseEntity<?> getSupply(
            @RequestParam(required = false) @Size(max = 2) TimestampParameter[] timestamp,
            @RequestParam(name = "q", required = false) SupplyType supplyType) {
        final var bound = Bound.of(timestamp, TIMESTAMP, FileData.FILE_DATA.CONSENSUS_TIMESTAMP);
        final var networkSupply = networkService.getSupply(bound);
```
