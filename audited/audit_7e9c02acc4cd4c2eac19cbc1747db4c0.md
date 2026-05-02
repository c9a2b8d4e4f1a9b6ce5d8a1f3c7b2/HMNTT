The key question is whether `NE:5` is accepted by the parser and then silently ignored in the loop. Let me trace the exact code path.

### Title
`NE` Operator Silently Ignored in `resolveRegisteredNodeIdBounds()`, Returning All Registered Nodes

### Summary
`RangeOperator.NE` is a fully parseable enum value accepted by `NumberRangeParameter.valueOf()`, but it is not handled in any branch of the `resolveRegisteredNodeIdBounds()` loop. When a caller supplies `registerednode.id=ne:5`, the constraint is silently discarded and the function returns `Range.closed(0L, Long.MAX_VALUE)`, causing the repository query to return every registered node. No authentication is required.

### Finding Description

**Parse path — `NE:5` is accepted without error:**

`RangeOperator.java` line 21 defines `NE` as a valid enum member: [1](#0-0) 

`RangeOperator.of()` resolves any non-`UNKNOWN` enum value successfully, so `RangeOperator.of("NE")` returns `RangeOperator.NE` without throwing: [2](#0-1) 

`NumberRangeParameter.valueOf("ne:5")` therefore produces `new NumberRangeParameter(RangeOperator.NE, 5L)` with no exception: [3](#0-2) 

**Loop path — `NE` falls through every branch:**

`hasLowerBound()` only covers `GT`, `GTE`, `EQ`; `hasUpperBound()` only covers `LT`, `LTE`. `NE` is absent from both: [4](#0-3) 

Inside `resolveRegisteredNodeIdBounds()`, the three-branch `if/else if/else if` chain tests `EQ`, `hasLowerBound()`, and `hasUpperBound()`. A `NE` parameter satisfies none of them and the loop body is a no-op: [5](#0-4) 

`lowerBound` remains `0L` and `upperBound` remains `Long.MAX_VALUE`. The function returns `Range.closed(0L, Long.MAX_VALUE)`: [6](#0-5) 

**Repository call — all rows returned:**

`getRegisteredNodes()` passes those bounds directly to the repository, which executes `WHERE registered_node_id >= 0 AND registered_node_id <= 9223372036854775807`: [7](#0-6) [8](#0-7) 

**Existing validation is insufficient:**

The `@Size(max = 2)` constraint on `registeredNodeIds` only limits the count of parameters, not the operator type: [9](#0-8) 

The controller adds no operator-type check for `registerednode.id`: [10](#0-9) 

The test suite's invalid-param list does not include `ne:N`, confirming the gap is untested: [11](#0-10) 

### Impact Explanation
An unprivileged external caller can enumerate the full registered-node registry regardless of any intended `ne:` filter. The response is indistinguishable from a legitimate unfiltered query, so API consumers (e.g., downstream services, dashboards) that trust the filter semantics will silently receive incorrect, over-broad data. This constitutes information disclosure and griefing of API correctness with no economic damage, matching the stated medium scope.

### Likelihood Explanation
No credentials or special network position are required — a single unauthenticated HTTP GET suffices. The `NE` operator string is documented in the error message of `RangeOperator.invalidOperator()` (`"Valid values: eq, gt, gte, lt, lte, ne"`), making it trivially discoverable by any caller who reads an error response. The attack is repeatable and stateless.

### Recommendation
1. **Reject `NE` at parse time** for `registerednode.id`: add `NE` to the invalid-operator test list and throw `IllegalArgumentException` in `RangeOperator.of()` (or a dedicated validator) when `NE` is supplied for parameters that do not support it.
2. **Add an explicit `else` / `default` branch** in `resolveRegisteredNodeIdBounds()` that throws `IllegalArgumentException("Unsupported operator: " + range.operator())` for any operator not handled, preventing future silent fall-throughs.
3. **Extend `hasLowerBound()`/`hasUpperBound()`** or add `isSupported()` to `RangeParameter` so that any operator outside the known set is flagged rather than silently ignored.

### Proof of Concept
```
# Precondition: mirror node REST-Java service running with ≥1 registered node

# Step 1 – confirm normal filter works (returns nothing for a non-existent id)
GET /api/v1/network/registered-nodes?registerednode.id=eq:999999
→ {"registeredNodes": []}

# Step 2 – supply NE operator; constraint is silently ignored
GET /api/v1/network/registered-nodes?registerednode.id=ne:999999
→ {"registeredNodes": [ <ALL registered nodes> ]}

# Step 3 – confirm NE is accepted (no 400 error)
# The operator string "ne" is valid per RangeOperator.of() and produces
# NumberRangeParameter(NE, 999999) which falls through all branches in
# resolveRegisteredNodeIdBounds(), leaving lowerBound=0, upperBound=MAX_VALUE.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/RangeOperator.java (L21-21)
```java
    NE("!=", Field::ne),
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/RangeOperator.java (L36-50)
```java
    public static RangeOperator of(String rangeOperator) {
        try {
            if (StringUtils.isBlank(rangeOperator)) {
                throw invalidOperator(rangeOperator);
            }

            final var operator = RangeOperator.valueOf(rangeOperator.toUpperCase());
            if (operator == UNKNOWN) {
                throw invalidOperator(rangeOperator);
            }
            return operator;
        } catch (IllegalArgumentException e) {
            throw invalidOperator(rangeOperator);
        }
    }
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/RangeParameter.java (L14-20)
```java
    default boolean hasLowerBound() {
        return operator() == RangeOperator.GT || operator() == RangeOperator.GTE || operator() == RangeOperator.EQ;
    }

    default boolean hasUpperBound() {
        return operator() == RangeOperator.LT || operator() == RangeOperator.LTE;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L145-151)
```java
        final var bounds = resolveRegisteredNodeIdBounds(request.getRegisteredNodeIds());
        final long lowerBound = bounds.lowerEndpoint();
        final long upperBound = bounds.upperEndpoint();

        final var nodeTypeId = nodeType != null ? nodeType.getId() : null;
        return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
                lowerBound, upperBound, nodeTypeId, page);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L41-44)
```java
    @Builder.Default
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();
```

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

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/NetworkControllerTest.java (L1945-1976)
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
