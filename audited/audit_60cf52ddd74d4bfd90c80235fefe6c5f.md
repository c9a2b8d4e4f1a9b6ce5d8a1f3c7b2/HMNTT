### Title
Long Overflow in `getInclusiveValue()` Causes `GT:Long.MAX_VALUE` Filter to Return All Registered Nodes

### Summary
In `NetworkServiceImpl.resolveRegisteredNodeIdBounds()`, when a user submits a `GT` operator with value `Long.MAX_VALUE` (9223372036854775807), `getInclusiveValue()` computes `Long.MAX_VALUE + 1` which silently overflows to `Long.MIN_VALUE`. `Math.max(0, Long.MIN_VALUE)` then evaluates to `0`, leaving `lowerBound` at `0` and `upperBound` at `Long.MAX_VALUE`, causing the repository query to return every registered node instead of an empty result.

### Finding Description

**Parsing — no rejection of `Long.MAX_VALUE`:** [1](#0-0) 

`getNumberValue()` only rejects negative values. `Long.MAX_VALUE` (9223372036854775807) is non-negative, so it passes.

**Overflow in `getInclusiveValue()`:** [2](#0-1) 

`Long.MAX_VALUE + 1` wraps to `Long.MIN_VALUE` (-9223372036854775808) with no overflow guard.

**Silently absorbed by `Math.max`:** [3](#0-2) 

`Math.max(0L, Long.MIN_VALUE)` = `0L`, so `lowerBound` is never updated from its initial value of `0`.

**Range guard bypassed:** [4](#0-3) 

`0 > Long.MAX_VALUE` is `false`, so no exception is thrown.

**Full-table query issued:** [5](#0-4) 

The repository is called with `lowerBound=0`, `upperBound=Long.MAX_VALUE`, returning all registered nodes.

### Impact Explanation
A semantically empty filter (`GT:Long.MAX_VALUE` — no node ID can satisfy this) is silently converted into a full-table scan. All registered nodes are returned to the caller. In the context of mirror-node data export, this means the mirror node receives a complete, unfiltered node list when it should receive nothing, violating data-integrity guarantees for downstream consumers.

### Likelihood Explanation
The exploit requires only a single, unauthenticated HTTP query parameter (`registeredNodeIds=gt:9223372036854775807`). No special privileges, tokens, or internal access are needed. The value is a valid non-negative long that passes all existing input validation. The attack is trivially repeatable and requires no brute-forcing or timing.

### Recommendation
1. **Guard against overflow in `getInclusiveValue()`** — use `Math.addExact` or an explicit bounds check:
   ```java
   if (operator == RangeOperator.GT) {
       if (value == Long.MAX_VALUE) throw new IllegalArgumentException("Value too large for GT operator");
       return value + 1;
   }
   ```
2. **Alternatively, reject `Long.MAX_VALUE` in `getNumberValue()`** for range-operator contexts.
3. **Post-overflow sanity check in `resolveRegisteredNodeIdBounds()`**: after computing the inclusive value, verify it is still `> value` for GT and `< value` for LT before applying `Math.max`/`Math.min`.

### Proof of Concept
```
GET /api/v1/network/nodes/registered?registeredNodeIds=gt:9223372036854775807
```
**Expected:** empty result set (no node ID can be > Long.MAX_VALUE).  
**Actual:** all registered nodes are returned.

Trace:
1. `NumberRangeParameter.valueOf("gt:9223372036854775807")` → `operator=GT, value=9223372036854775807` ✓ (passes `< 0` check)
2. `getInclusiveValue()` → `9223372036854775807 + 1` = `-9223372036854775808` (overflow)
3. `Math.max(0L, -9223372036854775808L)` = `0L` → `lowerBound` stays `0`
4. `0 > Long.MAX_VALUE` = `false` → no exception
5. `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(0, Long.MAX_VALUE, null, page)` → returns all rows

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java (L26-33)
```java
    private static long getNumberValue(String number) {
        var value = Long.parseLong(number);
        if (value < 0) {
            throw new IllegalArgumentException("Invalid range value");
        }

        return value;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java (L35-43)
```java
    public long getInclusiveValue() {
        if (operator == RangeOperator.GT) {
            return value + 1;
        } else if (operator == RangeOperator.LT) {
            return value - 1;
        } else {
            return value;
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L150-151)
```java
        return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
                lowerBound, upperBound, nodeTypeId, page);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L164-165)
```java
            } else if (range.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, range.getInclusiveValue());
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L171-173)
```java
        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
        }
```
