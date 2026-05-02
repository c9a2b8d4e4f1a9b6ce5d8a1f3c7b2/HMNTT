### Title
Unbounded Timestamp Range in `getHookStorage()` Enables Full Historical Table Scan DoS

### Summary
The `getHookStorage()` endpoint in `HooksController.java` accepts up to two `timestamp` parameters (`@Size(max = 2)`) with no maximum-range validation in the Java REST API path. An unauthenticated attacker can supply `timestamp=gte:0&timestamp=lte:99999999999.999999999`, triggering the historical code path and forcing a `DISTINCT ON (key)` PostgreSQL query to scan every row in `hook_storage_change` for the targeted `owner_id`/`hook_id` pair. Because `Bound.of()` is invoked with `primarySortField = false`, the only range guard in `Bound`'s constructor is silently skipped, and no equivalent of the Node.js `maxTimestampRange` (7-day cap) exists in the Java service.

### Finding Description

**Code path:**

1. `HooksController.java` line 110–111 — `@Size(max = 2)` permits two `TimestampParameter` values; no range-width constraint is declared. [1](#0-0) 

2. `HooksController.java` line 186 — `Bound.of(timestamps, TIMESTAMP, …)` is called. [2](#0-1) 

3. `Bound.java` line 181 — `Bound.of()` constructs the `Bound` with `primarySortField = false`, so the only guard (`if (primarySortField && adjustedLower > adjustedUpper)`) is never evaluated. [3](#0-2) 

4. `Bound.java` lines 63–96 — With `gte:0` the lower resolves to `0`; with `lte:99999999999.999999999` the upper resolves to the nanosecond representation of that value. If only one bound is supplied (e.g., `timestamp=gte:0`), `adjustUpperBound()` returns `Long.MAX_VALUE`. [4](#0-3) 

5. `HookStorageRequest.java` line 66–68 — Any non-empty `Bound` makes `isHistorical()` return `true`, routing execution to `getHookStorageChange()`. [5](#0-4) 

6. `HookServiceImpl.java` lines 97–114 — The resolved `[0, MAX_VALUE]` bounds are passed directly to the repository. [6](#0-5) 

7. `HookStorageChangeRepository.java` lines 15–31 — The native SQL uses `DISTINCT ON (key)` with `consensus_timestamp BETWEEN 0 AND <max>`. PostgreSQL must read and sort **every** row for the given `owner_id`/`hook_id` pair before it can apply the `LIMIT` from `Pageable`. [7](#0-6) 

**Root cause:** `Bound.of()` is always called with `primarySortField = false`, disabling the only in-constructor range check. No separate maximum-range guard (analogous to the Node.js `maxTimestampRange = 7d` in `rest/utils.js`) exists anywhere in the Java REST API for this endpoint. [8](#0-7) 

**Failed assumption:** The developers assumed that `LIMIT 100` (from `MAX_LIMIT`) would bound database work. It bounds *returned rows* but not the internal work of `DISTINCT ON`, which requires a full sequential scan of all qualifying rows before the limit is applied. [9](#0-8) 

### Impact Explanation
Each crafted request forces the database to perform a full index range scan over `hook_storage_change` for the targeted `(owner_id, hook_id)` pair across the entire consensus timestamp space. On a production node with months of hook activity, this translates to large I/O and CPU consumption per request. Because the endpoint is unauthenticated and the path parameters (`owner_id`, `hook_id`) are public, an attacker can issue these requests in a tight loop against multiple popular hook owners, driving database CPU/IO well above the 30% threshold cited in the scope without any brute-force credential guessing.

### Likelihood Explanation
The attack requires zero privileges: the endpoint is a public `GET`, the path parameters are enumerable from the `/hooks` listing endpoint, and the exploit payload is a two-parameter query string. It is trivially scriptable, repeatable at will, and requires no special tooling. The absence of rate limiting or timestamp-range enforcement in the Java service makes sustained exploitation straightforward.

### Recommendation
1. **Enforce a maximum timestamp range** in `Bound.of()` or in `HookServiceImpl.getHookStorageChange()`, mirroring the Node.js `maxTimestampRange` (e.g., 7 days). Reject or clamp requests where `adjustedUpper - adjustedLower` exceeds the configured maximum.
2. **Require both bounds** when the historical path is taken: reject requests that supply only a lower or only an upper timestamp bound (open-ended ranges), or default the missing bound to a narrow window (e.g., `now - 7d` to `now`).
3. **Change `primarySortField` to `true`** in `Bound.of()` for the timestamp parameter so the existing `adjustedLower > adjustedUpper` guard is at least active for inverted ranges. [3](#0-2) 

### Proof of Concept

```
# Step 1 – enumerate a valid owner_id and hook_id (public endpoint, no auth)
GET /api/v1/accounts/0.0.123/hooks
# → pick hook_id = 1 from response

# Step 2 – trigger full historical scan with maximum timestamp range
GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0&timestamp=lte:99999999999.999999999&limit=100

# Step 3 – repeat in a loop (e.g., 10 concurrent threads, 100 req/s each)
# Expected result: database CPU/IO rises sharply; each request forces
# DISTINCT ON scan of all hook_storage_change rows for owner 0.0.123 / hook 1
# across the entire consensus timestamp space [0, Long.MAX_VALUE].

# Variant using a single parameter (upper defaults to Long.MAX_VALUE):
GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0&limit=100
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L110-111)
```java
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L186-186)
```java
        final var bound = Bound.of(timestamps, TIMESTAMP, HookStorageChange.HOOK_STORAGE_CHANGE.CONSENSUS_TIMESTAMP);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L56-60)
```java
        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-97)
```java
    public long adjustUpperBound() {
        if (this.upper == null) {
            return Long.MAX_VALUE;
        }

        long upperBound = this.upper.value();
        if (this.upper.operator() == RangeOperator.LT) {
            upperBound--;
        }

        return upperBound;
    }

    public RangeParameter<Long> adjustLowerRange() {
        if (this.hasEqualBounds()) {
            // If the primary param has a range with a single value, rewrite it to EQ
            lower = new NumberRangeParameter(EQ, this.getAdjustedLowerRangeValue());
            upper = null;
        }

        return lower;
    }

    public long getAdjustedLowerRangeValue() {
        if (this.lower == null) {
            return 0;
        }

        long lowerBound = this.lower.value();
        if (this.lower.operator() == RangeOperator.GT) {
            lowerBound++;
        }

        return lowerBound;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L169-182)
```java
    public static Bound of(TimestampParameter[] timestamp, String parameterName, Field<Long> field) {
        if (timestamp == null || timestamp.length == 0) {
            return Bound.EMPTY;
        }

        for (int i = 0; i < timestamp.length; ++i) {
            final var param = timestamp[i];
            if (param.operator() == RangeOperator.EQ) {
                timestamp[i] = new TimestampParameter(RangeOperator.LTE, param.value());
            }
        }

        return new Bound(timestamp, false, parameterName, field);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L66-68)
```java
    public boolean isHistorical() {
        return !timestamp.isEmpty();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L97-114)
```java
        final var timestamp = request.getTimestamp();
        final long timestampLowerBound = timestamp.getAdjustedLowerRangeValue();
        final long timestampUpperBound = timestamp.adjustUpperBound();

        List<HookStorage> changes;

        if (requestHasKeys) {
            changes = hookStorageChangeRepository.findByKeyInAndTimestampBetween(
                    ownerId.getId(), hookId, keys, timestampLowerBound, timestampUpperBound, page);
        } else {
            changes = hookStorageChangeRepository.findByKeyBetweenAndTimestampBetween(
                    ownerId.getId(),
                    hookId,
                    request.getKeyLowerBound(),
                    request.getKeyUpperBound(),
                    timestampLowerBound,
                    timestampUpperBound,
                    page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L15-31)
```java
    @Query(nativeQuery = true, value = """
                    select distinct on (key)
                         owner_id,
                         hook_id,
                         key,
                         value_written       as "value",
                         consensus_timestamp as "modified_timestamp",
                         consensus_timestamp as "consensus_timestamp",
                         0                   as "created_timestamp",
                         (value_written is null or length(value_written) = 0) as "deleted"
                    from hook_storage_change
                    where owner_id = :ownerId
                      and hook_id = :hookId
                      and key >= :keyLowerBound
                      and key <= :keyUpperBound
                      and consensus_timestamp between :timestampLowerBound and :timestampUpperBound
                    """)
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L35-36)
```java
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```
