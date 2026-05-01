### Title
Silent Ignore of `NE` Operator for `node.id` in `getNetworkNodes()` Returns Unfiltered Result Set

### Summary
An unprivileged external user can supply `node.id=ne:<value>` to `GET /api/v1/network/nodes`. The `NE` operator is a valid, parseable `RangeOperator` but is not handled by any branch in the `nodeIdParams` loop inside `getNetworkNodes()`. It is silently dropped, causing the query to execute with no node ID filter at all — returning all nodes instead of the expected exclusion-filtered subset.

### Finding Description
**Parsing layer — no rejection of NE:**

`NumberRangeParameter.valueOf()` splits on `:` and calls `RangeOperator.of(splitVal[0])`, which successfully returns `RangeOperator.NE` for the string `"ne"`. [1](#0-0) 

`RangeOperator.NE` is a fully valid enum member — it is not `UNKNOWN`, so `RangeOperator.of()` does not throw. [2](#0-1) 

**Controller layer — no validation for `node.id` operators:**

`NetworkController.getNodes()` validates the operator only for `fileId` (line 155). There is no analogous check for any element of `nodeIds`. [3](#0-2) 

**Service layer — the silent drop:**

Inside `getNetworkNodes()`, each `nodeIdParam` is tested against three mutually exclusive branches:
- `operator() == RangeOperator.EQ` — false for NE
- `hasLowerBound()` — returns true only for GT, GTE, EQ — false for NE
- `hasUpperBound()` — returns true only for LT, LTE — false for NE

`NE` matches none of them and the loop body does nothing for it. [4](#0-3) [5](#0-4) 

After the loop, `nodeIds` is empty and `lowerBound=0`, `upperBound=Long.MAX_VALUE`. The repository call therefore returns every node in the address book. [6](#0-5) 

### Impact Explanation
A caller that sends `?node.id=ne:3` expects to receive all nodes *except* node 3. Instead it receives all nodes including node 3. The filter is completely ineffective. Downstream consumers that rely on the exclusion semantic (e.g., routing logic, monitoring dashboards, client-side pagination assumptions) receive a silently incorrect data set. There is no economic damage, but the API contract is violated and consumers are misled without any error signal.

### Likelihood Explanation
No privileges are required. The `ne` prefix is documented in the OpenAPI spec as a valid operator example for numeric parameters, making it discoverable by any developer reading the API docs. The request is trivially repeatable with a single HTTP GET. No authentication, rate-limit bypass, or special knowledge is needed. [7](#0-6) 

### Recommendation
Add an explicit rejection of the `NE` operator for `node.id` at the earliest possible point. The cleanest fix mirrors what `TimestampParameter` already does for its own NE case:

```java
// In NetworkController.getNodes(), after the fileId check:
for (var nodeIdParam : request.getNodeIds()) {
    if (nodeIdParam.operator() == RangeOperator.NE) {
        throw new IllegalArgumentException(
            "Not equal (ne) operator is not supported for node.id");
    }
}
```

Alternatively, add a default `else` branch inside the `getNetworkNodes()` loop that throws `IllegalArgumentException` for any unrecognised operator, so future operators cannot be silently ignored. [8](#0-7) 

### Proof of Concept
**Preconditions:** A running mirror-node REST-Java instance with at least two nodes in the address book (e.g., node IDs 1, 2, 3).

**Trigger:**
```
GET /api/v1/network/nodes?node.id=ne:2
```

**Expected result (correct behaviour):** Nodes 1 and 3 are returned; node 2 is excluded.

**Actual result (vulnerable behaviour):** Nodes 1, 2, and 3 are all returned. The `ne:2` parameter is silently ignored. The HTTP response is `200 OK` with no indication that the filter was not applied.

**Verification:** Compare with a valid operator:
```
GET /api/v1/network/nodes?node.id=gte:2   → returns nodes 2, 3  (filter applied)
GET /api/v1/network/nodes?node.id=ne:2    → returns nodes 1, 2, 3  (filter silently dropped)
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java (L17-23)
```java
        var splitVal = valueRangeParam.split(":");
        return switch (splitVal.length) {
            case 1 -> new NumberRangeParameter(RangeOperator.EQ, getNumberValue(splitVal[0]));
            case 2 -> new NumberRangeParameter(RangeOperator.of(splitVal[0]), getNumberValue(splitVal[1]));
            default ->
                throw new IllegalArgumentException("Invalid range operator. Should have format 'operator:number'");
        };
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/RangeOperator.java (L21-22)
```java
    NE("!=", Field::ne),
    UNKNOWN("unknown", null);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L154-157)
```java
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L110-118)
```java
        for (final var nodeIdParam : nodeIdParams) {
            if (nodeIdParam.operator() == RangeOperator.EQ) {
                nodeIds.add(nodeIdParam.value());
            } else if (nodeIdParam.hasLowerBound()) {
                lowerBound = Math.max(lowerBound, nodeIdParam.getInclusiveValue());
            } else if (nodeIdParam.hasUpperBound()) {
                upperBound = Math.min(upperBound, nodeIdParam.getInclusiveValue());
            }
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L124-136)
```java
        final Long[] nodeIdArray;
        if (!nodeIds.isEmpty()) {
            final var range = Range.closed(lowerBound, upperBound);
            nodeIdArray = nodeIds.stream().filter(range::contains).toArray(Long[]::new);
            if (nodeIdArray.length == 0) {
                return List.of();
            }
        } else {
            nodeIdArray = EMPTY_NODE_ID_ARRAY;
        }

        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/RangeParameter.java (L14-20)
```java
    default boolean hasLowerBound() {
        return operator() == RangeOperator.GT || operator() == RangeOperator.GTE || operator() == RangeOperator.EQ;
    }

    default boolean hasUpperBound() {
        return operator() == RangeOperator.LT || operator() == RangeOperator.LTE;
    }
```

**File:** rest/api/v1/openapi.yml (L4711-4728)
```yaml
        neOperator:
          summary: Example of not equals operator
          value: ne:300
        gtOperator:
          summary: Example of greater than operator
          value: gt:400
        gteOperator:
          summary: Example of greater than or equals operator
          value: gte:500
        ltOperator:
          summary: Example of less than operator
          value: lt:600
        lteOperator:
          summary: Example of less than or equals operator
          value: lte:700
      schema:
        type: string
        pattern: ^((gte?|lte?|eq|ne)\:)?\d{1,10}$
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/TimestampParameter.java (L40-43)
```java
        if (operator == RangeOperator.NE) {
            throw new IllegalArgumentException(ERROR);
        }

```
