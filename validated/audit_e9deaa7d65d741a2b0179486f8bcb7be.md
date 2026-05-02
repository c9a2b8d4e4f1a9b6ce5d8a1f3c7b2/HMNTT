I have all the code I need to evaluate this claim. Let me verify the exact lines for the SQL query ordering behavior.

All code references are verified. Every step in the exploit chain is confirmed by the actual source.

---

Audit Report

## Title
Unbounded Timestamp Range in `getHookStorageChange()` Enables Full Table Scan via `DISTINCT ON` Query

## Summary
Supplying a single lower-bound timestamp parameter (e.g., `timestamp=gte:0`) to the historical hook storage endpoint causes `isHistorical()` to return `true` while leaving the timestamp filter as `BETWEEN 0 AND 9223372036854775807` — a no-op. The resulting `DISTINCT ON (key) … ORDER BY key, consensus_timestamp DESC` query forces PostgreSQL to materialise every row for the given `owner_id`/`hook_id` before the `LIMIT` is applied, making repeated unauthenticated requests a practical DB I/O exhaustion vector.

## Finding Description

**Step 1 — `isHistorical()` is bypassed by a single-sided bound.**

`isHistorical()` returns `!timestamp.isEmpty()`, and `isEmpty()` returns `true` only when *both* `lower` and `upper` are `null`. [1](#0-0) [2](#0-1) 

Supplying `timestamp=gte:0` sets `lower` to `GTE(0)` and leaves `upper = null`, so `isEmpty()` is `false` and the historical code path in `getHookStorageChange()` is entered. [3](#0-2) 

**Step 2 — `adjustUpperBound()` returns `Long.MAX_VALUE` when `upper` is null.** [4](#0-3) 

**Step 3 — `getAdjustedLowerRangeValue()` returns `0` when `lower` is null, or `0` when `lower.value()` is `0` with `GTE`.** [5](#0-4) 

**Step 4 — The native SQL query receives `consensus_timestamp BETWEEN 0 AND 9223372036854775807`**, which matches every row ever written for that `owner_id`/`hook_id`. [6](#0-5) [7](#0-6) 

**Step 5 — `DISTINCT ON (key)` combined with `ORDER BY key, consensus_timestamp DESC` forces a full scan before `LIMIT` is applied.**

The `getPageRequest()` method appends `ORDER BY key ASC, consensus_timestamp DESC` for historical requests. PostgreSQL requires this ordering to satisfy `DISTINCT ON (key)`, meaning it must read and sort *all* matching rows before the `LIMIT` clause can discard any. [8](#0-7) [9](#0-8) 

**Why existing checks fail:**

The `Bound` constructor validates `adjustedLower > adjustedUpper` only when `primarySortField = true`. `Bound.of()` always passes `false`, so no range-width check is ever performed for timestamp bounds. [10](#0-9) [11](#0-10) 

## Impact Explanation
Every request with `timestamp=gte:0` (or any single lower-bound) triggers a full index-range scan of `hook_storage_change` for the targeted `owner_id`/`hook_id`, followed by a sort and deduplication pass for `DISTINCT ON`. On a production node with millions of storage-change records, each such request consumes significant DB I/O and CPU. A modest stream of concurrent unauthenticated requests can push DB I/O utilisation well above baseline, degrading service for all users. [12](#0-11) 

## Likelihood Explanation
The precondition is trivially met: any user who can reach the REST API endpoint can supply `timestamp=gte:0`. The attack is stateless, requires no authentication, and only needs a valid `owner_id` and `hook_id`, both of which are enumerable from public ledger data. No special tooling is required beyond a basic HTTP client. [13](#0-12) 

## Recommendation
1. **Require a bounded timestamp range for historical queries.** In `HookStorageRequest.isHistorical()` or in the controller layer, reject requests that supply only a lower bound without an upper bound, or enforce a maximum span (e.g., cap at 31 days in nanoseconds).
2. **Add a range-width check in `Bound.of()`** analogous to the `primarySortField` check already present in the `Bound` constructor — validate that `adjustedUpper - adjustedLower` does not exceed a configurable maximum.
3. **Consider rewriting the query** to avoid `DISTINCT ON` when the timestamp range is wide, or add a partial index on `(owner_id, hook_id, key, consensus_timestamp DESC)` so PostgreSQL can satisfy the `DISTINCT ON` via an index scan rather than a full sort. [14](#0-13) 

## Proof of Concept
```
# Enumerate a valid owner_id and hook_id from public ledger data, then:
GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage?timestamp=gte:0&limit=25

# This causes HookServiceImpl.getHookStorageChange() to execute:
#   SELECT DISTINCT ON (key) ... FROM hook_storage_change
#   WHERE owner_id = <ownerId>
#     AND hook_id  = <hookId>
#     AND key BETWEEN '\x00...' AND '\xFF...'
#     AND consensus_timestamp BETWEEN 0 AND 9223372036854775807
#   ORDER BY key ASC, consensus_timestamp DESC
#   LIMIT 25
#
# PostgreSQL must materialise and sort ALL rows for the given owner/hook
# before returning the first 25. Repeat concurrently to exhaust DB I/O.
``` [15](#0-14) [16](#0-15)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L40-41)
```java
    @Builder.Default
    private final Bound timestamp = Bound.EMPTY;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L54-63)
```java
    public PageRequest getPageRequest() {
        Sort sort;

        if (isHistorical()) {
            sort = Sort.by(new Sort.Order(order, Constants.KEY), new Sort.Order(Direction.DESC, CONSENSUS_TIMESTAMP));
        } else {
            sort = Sort.by(order, Constants.KEY);
        }

        return PageRequest.of(0, limit, sort);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/HookStorageRequest.java (L66-68)
```java
    public boolean isHistorical() {
        return !timestamp.isEmpty();
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L39-61)
```java
    public Bound(RangeParameter<Long>[] params, boolean primarySortField, String parameterName, Field<Long> field) {
        this.field = field;
        this.parameterName = parameterName;

        if (ArrayUtils.isEmpty(params)) {
            return;
        }

        for (var param : params) {
            if (param.hasLowerBound()) {
                lower = param;
            } else if (param.hasUpperBound()) {
                upper = param;
            }
            cardinality.merge(param.operator(), 1, Math::addExact);
        }

        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-66)
```java
    public long adjustUpperBound() {
        if (this.upper == null) {
            return Long.MAX_VALUE;
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L86-97)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L126-128)
```java
    public boolean isEmpty() {
        return lower == null && upper == null;
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L56-59)
```java
    public HookStorageResult getHookStorage(HookStorageRequest request) {
        if (request.isHistorical()) {
            return getHookStorageChange(request);
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L84-118)
```java
    private HookStorageResult getHookStorageChange(HookStorageRequest request) {
        final var page = request.getPageRequest();
        final var ownerId = entityService.lookup(request.getOwnerId());
        final long hookId = request.getHookId();

        final var keys = request.getKeys();
        final boolean requestHasKeys = !keys.isEmpty();
        final var keysInRange = request.getKeysInRange();

        if (keysInRange.isEmpty() && requestHasKeys) {
            return new HookStorageResult(ownerId, List.of());
        }

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
        }

        return new HookStorageResult(ownerId, changes);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L15-39)
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
    List<HookStorage> findByKeyBetweenAndTimestampBetween(
            long ownerId,
            long hookId,
            byte[] keyLowerBound,
            byte[] keyUpperBound,
            long timestampLowerBound,
            long timestampUpperBound,
            Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L97-99)
```java

```
