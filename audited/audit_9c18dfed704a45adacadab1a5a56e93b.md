### Title
Long Overflow in `getInclusiveValue()` Causes `GT:Long.MAX_VALUE` to Return All Registered Nodes

### Summary
In `NumberRangeParameter.getInclusiveValue()`, applying the `GT` operator to `Long.MAX_VALUE` causes `value + 1` to overflow to `Long.MIN_VALUE`. When this overflowed value is passed to `Math.max(0, Long.MIN_VALUE)` inside `resolveRegisteredNodeIdBounds()`, the lower bound silently resets to `0`, and the subsequent range check `0 > Long.MAX_VALUE` does not fire. The query then returns all registered nodes instead of none, causing incorrect records to be exported to mirror nodes.

### Finding Description

**Code path:**

`NumberRangeParameter.getInclusiveValue()` — [1](#0-0) 

```java
public long getInclusiveValue() {
    if (operator == RangeOperator.GT) {
        return value + 1;   // ← overflows when value == Long.MAX_VALUE
    }
    ...
}
```

`NumberRangeParameter.getNumberValue()` — [2](#0-1) 

Only rejects `value < 0`. `Long.MAX_VALUE` (9223372036854775807) passes this check.

`NetworkServiceImpl.resolveRegisteredNodeIdBounds()` — [3](#0-2) 

```java
} else if (range.hasLowerBound()) {
    lowerBound = Math.max(lowerBound, range.getInclusiveValue());
    // Math.max(0, Long.MIN_VALUE) == 0  ← overflow silently absorbed
}
...
if (lowerBound > upperBound) {   // 0 > Long.MAX_VALUE == false → no exception
    throw new IllegalArgumentException(...);
}
return Range.closed(lowerBound, upperBound);  // Range.closed(0, Long.MAX_VALUE)
```

**Exploit flow:**
1. Attacker sends `GET /api/v1/network/nodes/registered?registeredNodeId=gt:9223372036854775807`
2. `getNumberValue("9223372036854775807")` returns `Long.MAX_VALUE` (passes `< 0` guard).
3. `getInclusiveValue()` computes `Long.MAX_VALUE + 1` → wraps to `Long.MIN_VALUE`.
4. `Math.max(0L, Long.MIN_VALUE)` = `0L` — lower bound silently stays at 0.
5. Range check `0 > Long.MAX_VALUE` is false — no exception thrown.
6. `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(0, Long.MAX_VALUE, ...)` returns **all** registered nodes.

**Why existing checks fail:**
- `getNumberValue` only guards against negative input, not against `Long.MAX_VALUE` being used with `GT`. [2](#0-1) 
- `Math.max` silently absorbs the overflow instead of propagating an error. [4](#0-3) 
- The `lowerBound > upperBound` guard never fires because the overflowed value was already clamped to 0. [5](#0-4) 

### Impact Explanation
The endpoint `getRegisteredNodes` is used to export registered node records to mirror nodes. [6](#0-5)  A request with `gt:Long.MAX_VALUE` should return zero results (no node ID can exceed `Long.MAX_VALUE`), but instead returns the full set of registered nodes. This causes incorrect, unfiltered node data to be exported, violating the intended access/filter semantics of the API.

### Likelihood Explanation
No authentication or privilege is required. Any external user who can reach the REST API can craft the single-parameter request `registeredNodeId=gt:9223372036854775807`. The attack is trivially repeatable, requires no special tooling, and produces a deterministic result on every invocation.

### Recommendation
1. **In `getNumberValue`**: reject values that would overflow when used with `GT`/`LT` — e.g., disallow `Long.MAX_VALUE` for `GT` and `0` for `LT`, or use `Math.addExact` in `getInclusiveValue()` and catch `ArithmeticException` to throw an `IllegalArgumentException`.
2. **In `getInclusiveValue()`**: replace `value + 1` / `value - 1` with `Math.addExact(value, 1)` / `Math.addExact(value, -1)` so overflow throws instead of wrapping silently.

```java
public long getInclusiveValue() {
    try {
        if (operator == RangeOperator.GT) {
            return Math.addExact(value, 1);
        } else if (operator == RangeOperator.LT) {
            return Math.addExact(value, -1);
        }
    } catch (ArithmeticException e) {
        throw new IllegalArgumentException("Range value out of bounds for operator " + operator);
    }
    return value;
}
```

### Proof of Concept

```
GET /api/v1/network/nodes/registered?registeredNodeId=gt:9223372036854775807
```

**Expected:** 0 results (no node ID is greater than `Long.MAX_VALUE`).

**Actual:** All registered nodes returned (query executes as `WHERE registered_node_id BETWEEN 0 AND 9223372036854775807`).

Reproducible steps:
1. Start the mirror node REST-Java service with at least one registered node in the database.
2. Issue the HTTP request above with no authentication.
3. Observe that all registered nodes are returned in the response body instead of an empty list.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L139-152)
```java
    @Override
    public Collection<RegisteredNode> getRegisteredNodes(RegisteredNodesRequest request) {
        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE.REGISTERED_NODE_ID.getName());
        final var page = PageRequest.of(0, request.getLimit(), sort);

        final var nodeType = request.getType();
        final var bounds = resolveRegisteredNodeIdBounds(request.getRegisteredNodeIds());
        final long lowerBound = bounds.lowerEndpoint();
        final long upperBound = bounds.upperEndpoint();

        final var nodeTypeId = nodeType != null ? nodeType.getId() : null;
        return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
                lowerBound, upperBound, nodeTypeId, page);
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
