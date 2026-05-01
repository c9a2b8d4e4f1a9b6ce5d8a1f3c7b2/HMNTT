Tracing through the actual code carefully:

**Step 1 — `getAdjustedLowerRangeValue()` with GT and `Long.MAX_VALUE - 1`** [1](#0-0) 

`lowerBound = (Long.MAX_VALUE - 1) + 1 = Long.MAX_VALUE`. No overflow, no exception.

**Step 2 — `Bound` constructor range check is bypassed** [2](#0-1) 

The guard `adjustedLower > adjustedUpper` only fires when `primarySortField == true`. `Bound.of()` always passes `false`: [3](#0-2) 

**Step 3 — `getSupply()` range check also passes** [4](#0-3) 

`minTimestamp = Long.MAX_VALUE`, `maxTimestamp = Long.MAX_VALUE` (no upper bound → `adjustUpperBound()` returns `Long.MAX_VALUE`). `Long.MAX_VALUE > Long.MAX_VALUE` is `false`, so no exception.

**Step 4 — `Math.max` keeps `minTimestamp` at `Long.MAX_VALUE`** [5](#0-4) 

`getFirstDayOfMonth(Long.MAX_VALUE, -1)` resolves to a timestamp in year ~2262, far below `Long.MAX_VALUE`. `Math.max(Long.MAX_VALUE, <year2262>)` = `Long.MAX_VALUE`.

**Step 5 — Query returns zero rows → `EntityNotFoundException`** [6](#0-5) 

`WHERE ab.consensus_timestamp BETWEEN Long.MAX_VALUE AND Long.MAX_VALUE` matches nothing. `coalesce(max(consensus_timestamp), 0)` returns `0`. [7](#0-6) 

`consensusTimestamp() == 0L` → `EntityNotFoundException("Network supply not found")` → HTTP 404.

All five validation-gate checks pass. The vulnerability is real and exploitable by any unauthenticated caller.

---

### Title
Integer Boundary Bypass in `getSupply()` Allows Unauthenticated DoS via `gt:Long.MAX_VALUE-1` Timestamp

### Summary
An unprivileged caller can supply `timestamp=gt:9223372036854775806` (`Long.MAX_VALUE - 1`) to the network supply endpoint. `getAdjustedLowerRangeValue()` increments this to `Long.MAX_VALUE`, all existing range guards pass because the adjusted lower equals the adjusted upper, and the resulting database query matches no rows, causing `EntityNotFoundException` (HTTP 404) for every such request. No authentication or special privilege is required.

### Finding Description
**Code path:** `NetworkServiceImpl.getSupply()` → `Bound.getAdjustedLowerRangeValue()` → `AccountBalanceRepository.getSupplyHistory()`

**Root cause:** `getAdjustedLowerRangeValue()` unconditionally increments a GT lower bound by 1 with no ceiling check:

```java
// Bound.java:92-94
if (this.lower.operator() == RangeOperator.GT) {
    lowerBound++;   // Long.MAX_VALUE - 1 + 1 = Long.MAX_VALUE, no overflow
}
```

The only constructor-level guard (`adjustedLower > adjustedUpper`) is gated on `primarySortField == true`, which is always `false` for timestamp bounds created via `Bound.of()`. The service-level guard (`minTimestamp > maxTimestamp`) also passes because both values equal `Long.MAX_VALUE`. `Math.max(Long.MAX_VALUE, optimalLowerBound)` preserves `Long.MAX_VALUE` as `minTimestamp`. The repository query `WHERE consensus_timestamp BETWEEN Long.MAX_VALUE AND Long.MAX_VALUE` returns zero rows; `coalesce(max(consensus_timestamp), 0)` returns `0`; the `consensusTimestamp() == 0L` check throws `EntityNotFoundException`.

**Why checks fail:**
- `Bound` constructor guard: skipped (`primarySortField = false`)
- Service range guard: `Long.MAX_VALUE > Long.MAX_VALUE` is `false`
- No upper-bound cap on accepted timestamp values anywhere in the parsing or service layer

### Impact Explanation
Any caller can make the `/api/v1/network/supply?timestamp=gt:9223372036854775806` endpoint return HTTP 404 unconditionally, denying legitimate consumers (wallets, explorers, monitoring tools) access to current supply data. Because the endpoint is stateless and unauthenticated, the attack is trivially repeatable and requires no setup. Severity: **Medium** (availability impact on a public read endpoint; no data corruption or authentication bypass).

### Likelihood Explanation
The attack requires only a single HTTP GET request with a crafted query parameter. No account, token, or prior knowledge of the system is needed. The parameter value is a plain decimal integer within the valid `long` range, so it passes any basic type-level parsing. Repeatability is unlimited. Likelihood: **High**.

### Recommendation
Add an explicit upper-bound cap on accepted timestamp values before the `Bound` is constructed, e.g., reject any timestamp value greater than `Instant.now().toEpochMilli() * 1_000_000` plus a small future tolerance. Additionally, add a ceiling check inside `getAdjustedLowerRangeValue()`:

```java
if (this.lower.operator() == RangeOperator.GT) {
    if (lowerBound == Long.MAX_VALUE) {
        throw new IllegalArgumentException("Timestamp lower bound too large");
    }
    lowerBound++;
}
```

And enforce the `primarySortField` guard unconditionally for timestamp bounds, or add an equivalent check in `getSupply()` before calling the repository.

### Proof of Concept
```
GET /api/v1/network/supply?timestamp=gt:9223372036854775806
```
1. No authentication required.
2. `TimestampParameter` parses operator=GT, value=9223372036854775806.
3. `Bound.of()` creates a `Bound` with `primarySortField=false`; constructor range check is skipped.
4. `getSupply()`: `minTimestamp = getAdjustedLowerRangeValue() = Long.MAX_VALUE`; `maxTimestamp = adjustUpperBound() = Long.MAX_VALUE`.
5. Guard `minTimestamp > maxTimestamp` → `false`; execution continues.
6. `getFirstDayOfMonth(Long.MAX_VALUE, -1)` returns ~year-2262 timestamp; `Math.max(Long.MAX_VALUE, <year2262>) = Long.MAX_VALUE`.
7. `getSupplyHistory(..., Long.MAX_VALUE, Long.MAX_VALUE)` → zero rows → `consensusTimestamp = 0`.
8. `throw new EntityNotFoundException("Network supply not found")` → HTTP 404.
9. Repeat indefinitely; every request returns 404.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/Bound.java (L56-60)
```java
        long adjustedLower = getAdjustedLowerRangeValue();
        long adjustedUpper = adjustUpperBound();
        if (primarySortField && adjustedLower > adjustedUpper) {
            throw new IllegalArgumentException("Invalid range provided for %s".formatted(parameterName));
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L69-75)
```java
            var minTimestamp = timestamp.getAdjustedLowerRangeValue();
            final var maxTimestamp = timestamp.adjustUpperBound();

            // Validate timestamp range
            if (minTimestamp > maxTimestamp) {
                throw new IllegalArgumentException("Invalid range provided for timestamp");
            }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L77-78)
```java
            final var optimalLowerBound = getFirstDayOfMonth(maxTimestamp, -1);
            minTimestamp = Math.max(minTimestamp, optimalLowerBound);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L84-87)
```java
        if (networkSupply.consensusTimestamp() == 0L) {
            throw new EntityNotFoundException("Network supply not found");
        }

```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/AccountBalanceRepository.java (L21-21)
```java
      where ab.consensus_timestamp between :lowerTimestamp and :upperTimestamp
```
