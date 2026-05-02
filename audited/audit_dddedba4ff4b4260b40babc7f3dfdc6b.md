### Title
Unbounded Timestamp Range in `getHookStorageChange()` Enables Full Table Scan DoS

### Summary
An unprivileged user can craft a `HookStorageRequest` with a near-unbounded `timestamp` range (e.g., `GT:0` with no upper bound), causing `getHookStorageChange()` to issue a SQL query scanning virtually all rows in `hook_storage_change`. No maximum-range validation exists for the timestamp `Bound` because the only range-validity check is gated on `primarySortField=true`, which is always `false` for timestamp parameters. This allows repeated, cheap HTTP requests to drive sustained high I/O and CPU load on the mirror node.

### Finding Description

**Code path:**

`HookServiceImpl.getHookStorageChange()` (lines 97–114) reads the timestamp bounds directly from the `Bound` object and passes them to the repository:

```java
final long timestampLowerBound = timestamp.getAdjustedLowerRangeValue();  // line 98
final long timestampUpperBound = timestamp.adjustUpperBound();             // line 99
```

`Bound.getAdjustedLowerRangeValue()` (lines 86–97):
- Returns `0` when `lower == null`
- Returns `value + 1` when operator is `GT` — so `GT:0` → `1`

`Bound.adjustUpperBound()` (lines 63–74):
- Returns `Long.MAX_VALUE` when `upper == null`

**Root cause — the only range check is bypassed:**

In `Bound`'s constructor (lines 56–60):
```java
if (primarySortField && adjustedLower > adjustedUpper) {
    throw new IllegalArgumentException(...);
}
```
`Bound.of()` (line 181) always passes `primarySortField = false` for timestamp, so this guard never fires for timestamp parameters. No maximum-span check exists anywhere.

**Exploit flow:**

A user sends `timestamp=gt:0` with no upper bound:
- `lower` = `GT:0` → `getAdjustedLowerRangeValue()` = `1`
- `upper` = `null` → `adjustUpperBound()` = `Long.MAX_VALUE`
- `isHistorical()` = `true` (Bound is non-empty)
- Repository query becomes:
  ```sql
  SELECT DISTINCT ON (key) ... FROM hook_storage_change
  WHERE owner_id = ? AND hook_id = ?
    AND consensus_timestamp BETWEEN 1 AND 9223372036854775807
  ```

The `DISTINCT ON (key)` clause forces the database to sort and scan **all matching rows** before returning the paginated result, regardless of the `limit` (default 25).

**Why existing checks fail:**

| Check | Why insufficient |
|---|---|
| `primarySortField` range guard | Always `false` for timestamp |
| `limit` / `PageRequest` | Applied after full scan for `DISTINCT ON` |
| `Bound.of()` EQ→LTE rewrite | Only rewrites operator, adds no range cap |
| `verifySingleOccurrence()` | Validates operator count, not range width |

### Impact Explanation
Every such request forces a full sequential scan of `hook_storage_change` filtered only by `owner_id` and `hook_id`. With a large table, this translates directly to high disk I/O, CPU (sort for `DISTINCT ON`), and memory pressure on the database backend. An attacker sending a modest rate of concurrent requests (no brute force needed — each request is individually expensive) can sustain >30% resource elevation on the mirror node's database tier. The endpoint is publicly accessible with no authentication requirement.

### Likelihood Explanation
The exploit requires zero privileges, zero authentication, and only a single crafted HTTP parameter (`timestamp=gt:0`). It is trivially repeatable and scriptable. The attacker needs only to know the `ownerId` and `hookId` of any existing hook (both are enumerable from other public endpoints). The attack is stable across restarts and does not require any state.

### Recommendation
1. **Enforce a maximum timestamp span** in `Bound.of()` or in the controller/validator layer. Reject or cap requests where `adjustUpperBound() - getAdjustedLowerRangeValue()` exceeds a configurable maximum (e.g., 24 hours in nanoseconds).
2. **Require at least one bound to be present and recent** for historical queries — e.g., reject requests where `upper` is `null` or where `lower` is below `(now - maxWindow)`.
3. **Add a database-level timeout** on historical queries as a defense-in-depth measure.
4. Consider **rate-limiting** the historical storage endpoint per caller IP/entity.

### Proof of Concept

```
GET /api/v1/hooks/{ownerId}/storage?hookId={hookId}&timestamp=gt:0
```

No authentication header required.

- `timestamp=gt:0` sets `lower = GT:0`, `upper = null`
- `isHistorical()` → `true`
- `timestampLowerBound` = `1`, `timestampUpperBound` = `Long.MAX_VALUE`
- Executes: `SELECT DISTINCT ON (key) ... FROM hook_storage_change WHERE owner_id=? AND hook_id=? AND consensus_timestamp BETWEEN 1 AND 9223372036854775807`
- Repeat in a loop (e.g., 10–20 concurrent requests) to sustain elevated resource consumption.

Relevant code locations: [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L97-115)
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
        }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageChangeRepository.java (L25-39)
```java
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
