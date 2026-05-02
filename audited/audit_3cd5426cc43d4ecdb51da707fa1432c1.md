Now I have all the information needed. Let me trace the full exploit path precisely.

### Title
Integer Overflow in `getInclusiveValue()` Causes `gt:Long.MAX_VALUE` to Return All Registered Nodes

### Summary
`NumberRangeParameter.getInclusiveValue()` performs an unchecked `value + 1` when the operator is `GT`. When a user supplies `registerednode.id=gt:9223372036854775807` (Long.MAX_VALUE), the addition silently overflows to `Long.MIN_VALUE`. `Math.max(0L, Long.MIN_VALUE)` then resets `lowerBound` back to `0`, the `lowerBound > upperBound` guard evaluates to `false`, and the repository query executes with the full range `[0, Long.MAX_VALUE]`, returning every registered node instead of an empty result.

### Finding Description

**Step 1 — Input accepted without overflow guard**

`NumberRangeParameter.valueOf("gt:9223372036854775807")` calls `getNumberValue`:

```java
// NumberRangeParameter.java line 26-33
private static long getNumberValue(String number) {
    var value = Long.parseLong(number);
    if (value < 0) {
        throw new IllegalArgumentException("Invalid range value");
    }
    return value;
}
```

`Long.MAX_VALUE` (9223372036854775807) is ≥ 0, so it passes. The test suite at `NetworkControllerTest.java:1964` only rejects `"9223372036854775808"` (which overflows `Long.parseLong`), not `"gt:9223372036854775807"`.

**Step 2 — Silent overflow in `getInclusiveValue()`**

```java
// NumberRangeParameter.java line 35-43
public long getInclusiveValue() {
    if (operator == RangeOperator.GT) {
        return value + 1;   // Long.MAX_VALUE + 1 = Long.MIN_VALUE (overflow)
    }
    ...
}
``` [1](#0-0) 

**Step 3 — `Math.max` absorbs the overflow**

```java
// NetworkServiceImpl.java line 154-176
long lowerBound = 0L;
long upperBound = MAX_VALUE;
...
} else if (range.hasLowerBound()) {
    lowerBound = Math.max(lowerBound, range.getInclusiveValue());
    // Math.max(0L, Long.MIN_VALUE) = 0L  ← overflow silently absorbed
}
...
if (lowerBound > upperBound) {   // 0L > Long.MAX_VALUE = false → no exception
    throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
}
return Range.closed(lowerBound, upperBound);  // Range.closed(0, Long.MAX_VALUE)
``` [2](#0-1) 

**Step 4 — Repository query returns all rows**

```java
// NetworkServiceImpl.java line 150-151
return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
        0L, Long.MAX_VALUE, nodeTypeId, page);
```

The underlying SQL is:

```sql
-- RegisteredNodeRepository.java line 14-20
select * from registered_node
where registered_node_id >= 0
  and registered_node_id <= 9223372036854775807
  and deleted is false
  and (:type is null or type @> array[:type]::smallint[])
``` [3](#0-2) 

This matches every row in the table.

### Impact Explanation

A semantically empty query (`gt:Long.MAX_VALUE` — no node ID can exceed Long.MAX_VALUE) is silently rewritten into a full-table scan returning all registered nodes. Any pagination limit still applies, but the attacker receives data they should not receive (an empty list). Depending on what `registered_node` contains (admin keys, service endpoints, internal topology), this constitutes an information-disclosure vulnerability. The incorrect result also breaks any caller logic that relies on an empty response to mean "no such node exists."

### Likelihood Explanation

No authentication or special privilege is required. The endpoint `GET /api/v1/network/registered-nodes` is publicly accessible. The payload is a single, well-formed query parameter. The value `9223372036854775807` is the documented `Long.MAX_VALUE` constant, trivially known to any attacker. The attack is deterministic and repeatable with zero side effects, making it low-risk for the attacker to probe repeatedly.

### Recommendation

1. **Guard against overflow before arithmetic** in `getInclusiveValue()`:

```java
public long getInclusiveValue() {
    if (operator == RangeOperator.GT) {
        if (value == Long.MAX_VALUE) {
            throw new IllegalArgumentException("Value too large for GT operator");
        }
        return value + 1;
    } else if (operator == RangeOperator.LT) {
        if (value == 0) {
            throw new IllegalArgumentException("Value too small for LT operator");
        }
        return value - 1;
    }
    return value;
}
```

2. Alternatively, use `Math.addExact(value, 1)` which throws `ArithmeticException` on overflow, and map that to a 400 Bad Request.

3. Add `"gt:9223372036854775807"` and `"gte:9223372036854775807"` to the `invalidIdParam` test cases in `NetworkControllerTest.java` to prevent regression. [4](#0-3) 

### Proof of Concept

**Precondition:** Mirror node REST-Java service is running with at least one registered node in the database.

**Request:**
```
GET /api/v1/network/registered-nodes?registerednode.id=gt:9223372036854775807
```

**Expected result:** Empty `registeredNodes` array (no node ID can be > Long.MAX_VALUE).

**Actual result:** All registered nodes are returned (up to the configured page limit).

**Trace:**
```
valueOf("gt:9223372036854775807")
  → getNumberValue("9223372036854775807") = 9223372036854775807L  [passes value < 0 check]
  → NumberRangeParameter(GT, 9223372036854775807L)

getInclusiveValue()
  → 9223372036854775807L + 1L = -9223372036854775808L  [Long.MIN_VALUE, silent overflow]

resolveRegisteredNodeIdBounds()
  → Math.max(0L, -9223372036854775808L) = 0L
  → lowerBound=0, upperBound=Long.MAX_VALUE
  → 0 > Long.MAX_VALUE = false  [guard bypassed]
  → Range.closed(0, Long.MAX_VALUE)

SQL: registered_node_id >= 0 AND registered_node_id <= 9223372036854775807
  → returns ALL rows
```

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L154-176)
```java
    private static Range<Long> resolveRegisteredNodeIdBounds(List<NumberRangeParameter> registeredNodeIdRanges) {
        long lowerBound = 0L;
        long upperBound = MAX_VALUE;

        for (final var range : registeredNodeIdRanges) {
            if (range.operator() == RangeOperator.EQ) {
                if (registeredNodeIdRanges.size() > 1) {
                    throw new IllegalArgumentException("The 'eq' operator cannot be combined with other operators");
                }
                return Range.closed(range.value(), range.value());
            } else if (range.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, range.getInclusiveValue());
            } else if (range.hasUpperBound()) {
                upperBound = Math.min(upperBound, range.getInclusiveValue());
            }
        }

        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
        }

        return Range.closed(lowerBound, upperBound);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java (L14-22)
```java
    @Query(value = """
            select * from registered_node
            where registered_node_id >= :lowerBound
            and registered_node_id <= :upperBound
            and deleted is false
            and (:type is null or type @> array[:type]::smallint[])
            """, nativeQuery = true)
    List<RegisteredNode> findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
            long lowerBound, long upperBound, @Nullable Short type, Pageable pageable);
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/NetworkControllerTest.java (L1950-1981)
```java
        @ParameterizedTest
        @ValueSource(
                strings = {
                    "invalid",
                    "-1",
                    "eq:-1",
                    "lt:-1",
                    "lte:-1",
                    "gt:-1",
                    "gte:-1",
                    "lt:invalid",
                    "gt:abc",
                    "eq:abc",
                    ".1",
                    "9223372036854775808",
                    "a:1",
                    "eq:1:2",
                })
        void invalidIdParam(String registeredNodeIdParam) {
            // given
            setupRegisteredNodeData();

            // when/then
            validateError(
                    () -> restClient
                            .get()
                            .uri("?registerednode.id=%s".formatted(registeredNodeIdParam))
                            .retrieve()
                            .toEntity(String.class),
                    HttpClientErrorException.BadRequest.class,
                    "Invalid parameter: registerednode.id");
        }
```
