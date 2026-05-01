### Title
Off-by-One in `lt:1` Bound Resolution Allows Unintended Query for `registered_node_id = 0`

### Summary
When an unprivileged caller sends `GET /api/v1/network/registered-nodes?registerednode.id=lt:1`, the `getInclusiveValue()` method returns `0` (i.e., `1 - 1`), and because `lowerBound` defaults to `0`, the guard `lowerBound > upperBound` evaluates to `0 > 0` — which is `false` — so no exception is thrown. The resulting query searches for `registered_node_id BETWEEN 0 AND 0`, returning any non-deleted node whose database primary key is `0`. This is an unintended code path: the developer's intent was that `lt:1` would produce an empty or invalid range, not a pinpoint query for `id = 0`.

### Finding Description

**Code path:**

1. `GET /api/v1/network/registered-nodes?registerednode.id=lt:1` is accepted by `NetworkController.getRegisteredNodes()`. [1](#0-0) 

2. `NumberRangeParameter.valueOf("lt:1")` produces `(operator=LT, value=1)`. `getNumberValue` only rejects values `< 0`, so `1` passes. [2](#0-1) 

3. In `resolveRegisteredNodeIdBounds()`, `lowerBound` is initialised to `0L`. For the `lt:1` parameter, `hasUpperBound()` is `true`, so `upperBound = Math.min(MAX_VALUE, getInclusiveValue())` = `Math.min(MAX_VALUE, 0)` = `0`. [3](#0-2) 

4. The only guard is `if (lowerBound > upperBound)`. With both equal to `0`, the condition is `false` and no exception is thrown. [4](#0-3) 

5. `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(0, 0, null, page)` executes:
   ```sql
   SELECT * FROM registered_node
   WHERE registered_node_id >= 0
     AND registered_node_id <= 0
     AND deleted IS FALSE
   ``` [5](#0-4) 

**Root cause:** `getInclusiveValue()` for `LT` subtracts 1 from the user-supplied value without a floor check, and the range-validity guard uses strict inequality (`>`), so the degenerate `[0, 0]` range silently passes through.

**Why existing checks fail:**
- `getNumberValue` rejects negative *input* values but does not prevent `getInclusiveValue()` from producing `0` when the input is `1`.
- The `lowerBound > upperBound` guard uses `>` not `>=`, so an equal pair `(0, 0)` is treated as valid.
- The design document confirms `registered_node_id` values can start at `0` (`"associated_registered_nodes": [0, 1, 5, 10]`), so a node with `id = 0` can legitimately exist in the database. [6](#0-5) 

### Impact Explanation
If a registered node with `registered_node_id = 0` exists and is not soft-deleted, its full record — including `service_endpoints` (IP addresses, ports, domain names), `admin_key`, and `type` — is returned to any unauthenticated caller. This constitutes unintended information disclosure of infrastructure endpoint data. The "network shutdown" severity label in the question is not supported by the code; the actual impact is **information disclosure** (low-to-medium severity), which could assist an attacker in targeting a specific node's network endpoints.

### Likelihood Explanation
The exploit requires zero privileges, zero authentication, and a single HTTP GET request. The parameter `registerednode.id=lt:1` is syntactically valid and passes all input validation. Any external user who reads the API documentation (which explicitly lists `lt` as a supported operator) can reproduce this in seconds. Repeatability is unlimited.

### Recommendation
Apply two independent fixes:

1. **Floor `getInclusiveValue()` at `0`** in `NumberRangeParameter`:
   ```java
   } else if (operator == RangeOperator.LT) {
       if (value == 0) throw new IllegalArgumentException("lt:0 produces no valid IDs");
       return value - 1;
   }
   ```

2. **Change the range guard to `>=`** in `resolveRegisteredNodeIdBounds()`:
   ```java
   if (lowerBound >= upperBound && /* not a single-point EQ */ ...) {
       throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
   }
   ```
   Or, more precisely, reject any `lt:N` where `N <= lowerBound` before computing the range.

### Proof of Concept
**Precondition:** A `registered_node` row with `registered_node_id = 0` and `deleted = false` exists in the database (plausible per design doc).

**Steps:**
```
GET /api/v1/network/registered-nodes?registerednode.id=lt:1
```

**Expected (correct) behaviour:** Empty result or `400 Bad Request`.

**Actual behaviour:** Returns the node record for `registered_node_id = 0`, including its `service_endpoints`, `admin_key`, and `type`.

**Trace:**
- `NumberRangeParameter(LT, 1).getInclusiveValue()` → `0`
- `resolveRegisteredNodeIdBounds`: `lowerBound=0`, `upperBound=0`, guard `0 > 0` → false
- SQL: `WHERE registered_node_id >= 0 AND registered_node_id <= 0 AND deleted IS FALSE`
- Node with `id=0` returned to caller.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L173-187)
```java
    @GetMapping("/registered-nodes")
    RegisteredNodesResponse getRegisteredNodes(@RequestParameter RegisteredNodesRequest request) {
        final var registeredNodes = networkService.getRegisteredNodes(request);
        final var registeredNodeDtos = registeredNodeMapper.map(registeredNodes);

        final var sort = Sort.by(request.getOrder(), REGISTERED_NODE_ID);
        final var pageable = PageRequest.of(0, request.getLimit(), sort);
        final var links = linkFactory.create(registeredNodeDtos, pageable, REGISTERED_NODE_EXTRACTOR);

        final var response = new RegisteredNodesResponse();
        response.setRegisteredNodes(registeredNodeDtos);
        response.setLinks(links);

        return response;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/NumberRangeParameter.java (L26-43)
```java
    private static long getNumberValue(String number) {
        var value = Long.parseLong(number);
        if (value < 0) {
            throw new IllegalArgumentException("Invalid range value");
        }

        return value;
    }

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L154-168)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L171-175)
```java
        if (lowerBound > upperBound) {
            throw new IllegalArgumentException("Invalid range: lower bound exceeds upper bound");
        }

        return Range.closed(lowerBound, upperBound);
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

**File:** docs/design/block-node-discoverabilty.md (L284-284)
```markdown
        "associated_registered_nodes": [0, 1, 5, 10],
```
