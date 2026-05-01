The key code path to trace:

1. `NumberRangeParameter.getNumberValue("0")` — `Long.parseLong("0")` = 0, and `0 < 0` is **false**, so the negative-value guard does **not** fire. `LT:0` is accepted.
2. In `getNetworkNodes()`, `nodeIdParam.hasUpperBound()` is true for `LT`, so `upperBound = Math.min(Long.MAX_VALUE, nodeIdParam.getInclusiveValue())` is called.
3. `getInclusiveValue()` for `LT` returns `value - 1 = 0 - 1 = -1`.
4. `upperBound` becomes `-1`; `lowerBound` stays at `0`.
5. `lowerBound > upperBound` → `0 > -1` → `true` → `IllegalArgumentException` thrown before any DB call.

---

### Title
`LT:0` Bypasses Input Validation, Triggering Predictable 400 Errors via Impossible Range

### Summary
`NumberRangeParameter.getNumberValue()` rejects negative literal values but accepts `0`, allowing `node.id=lt:0` to pass parsing. `getInclusiveValue()` then computes `0 - 1 = -1` as the upper bound, which is below the default lower bound of `0`, unconditionally triggering an `IllegalArgumentException` before any database work is done. Any unauthenticated caller can reproduce this deterministically.

### Finding Description
**File:** `rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java`

`getNumberValue()` (lines 26–33) only guards against `value < 0`: [1](#0-0) 

The value `0` passes this check. `getInclusiveValue()` (lines 35–43) then applies `value - 1` for `LT`, yielding `-1`: [2](#0-1) 

In `NetworkServiceImpl.getNetworkNodes()` (lines 107–122), `upperBound` is set to `-1` via `Math.min`, and the subsequent guard `lowerBound > upperBound` (`0 > -1`) throws `IllegalArgumentException("Invalid range provided for node.id")` every time: [3](#0-2) 

The existing guard in `getNumberValue()` is insufficient because it validates the raw literal, not the semantic validity of the operator+value combination. `LT:0` is semantically impossible (no node ID can be less than 0) but syntactically accepted.

### Impact Explanation
Every request with `node.id=lt:0` returns HTTP 400 without touching the database. If the exception handler logs at WARN/ERROR level, high-volume repetition pollutes logs and may obscure real errors. Thread consumption per request is negligible (exception thrown in-memory), so resource exhaustion is not a realistic concern. Impact is limited to log noise and minor operational friction — consistent with the "griefing, no economic damage" classification.

### Likelihood Explanation
No authentication or special privilege is required. The endpoint is publicly accessible (`GET /api/v1/network/nodes`). The trigger is a single, deterministic query parameter. Any attacker or automated scanner can discover and repeat it trivially.

### Recommendation
Add a semantic validation step in `NumberRangeParameter.getNumberValue()` or at the operator+value combination level: reject `LT` or `LTE` with a value of `0` (since the inclusive upper bound would be `-1`, below the minimum valid node ID). Alternatively, add a pre-check in `getNetworkNodes()` before computing `getInclusiveValue()` — if the operator is `LT` and the value is `0`, throw a descriptive `IllegalArgumentException` immediately with a message like `"node.id lt:0 produces an empty range; minimum node ID is 0"`. The same pattern should be audited in `resolveRegisteredNodeIdBounds()` for the registered-nodes endpoint. [4](#0-3) 

### Proof of Concept
```
# No authentication required
curl -s "https://<mirror-node-host>/api/v1/network/nodes?node.id=lt:0"

# Expected response: HTTP 400
# {"_status":{"messages":[{"message":"Invalid range provided for node.id"}]}}

# Repeatable indefinitely; each request triggers the exception path
# in NetworkServiceImpl.getNetworkNodes() at the lowerBound > upperBound check
# without executing any database query.
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L107-122)
```java
        long lowerBound = 0L;
        long upperBound = Long.MAX_VALUE;

        for (final var nodeIdParam : nodeIdParams) {
            if (nodeIdParam.operator() == RangeOperator.EQ) {
                nodeIds.add(nodeIdParam.value());
            } else if (nodeIdParam.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, nodeIdParam.getInclusiveValue());
            } else if (nodeIdParam.hasUpperBound()) {
                upperBound = Math.min(upperBound, nodeIdParam.getInclusiveValue());
            }
        }

        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range provided for node.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L154-173)
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
```
