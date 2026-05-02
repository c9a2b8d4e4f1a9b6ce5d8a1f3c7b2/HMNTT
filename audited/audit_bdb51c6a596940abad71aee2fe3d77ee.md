### Title
Unbounded `node.id` Array Parameter Enables DoS on `/api/v1/network/nodes` Endpoint

### Summary
The `NetworkNodeRequest.nodeIds` field accepts an unbounded `List<NumberRangeParameter>` with no `@Size` constraint, unlike the analogous `RegisteredNodesRequest.registeredNodeIds` which enforces `@Size(max = 2)`. An unauthenticated attacker can supply thousands of `node.id=eq:X` query parameters, causing the service to build an arbitrarily large `Long[]` array that is passed directly into the `abe.node_id = any(:nodeIds)` SQL clause, exhausting JDBC parameter binding resources and database query planning overhead, and denying legitimate users access to node endpoint data.

### Finding Description
**Code path:**

- `NetworkNodeRequest.nodeIds` — `List<NumberRangeParameter>` with no `@Size` annotation: [1](#0-0) 

- Compare with `RegisteredNodesRequest.registeredNodeIds`, which correctly enforces `@Size(max = 2)`: [2](#0-1) 

- `NetworkServiceImpl.getNetworkNodes()` iterates all `nodeIdParams` with no size guard, adding every `EQ` value into a `HashSet<Long>`, then streaming it to an unbounded `Long[]`: [3](#0-2) 

- The resulting array is passed directly to the native SQL query's `any(:nodeIds)` clause with no size limit: [4](#0-3) 

**Root cause:** The `nodeIds` list in `NetworkNodeRequest` has no `@Size` constraint. The `limit` parameter is capped at 25 (`MAX_LIMIT`) but this only restricts *output rows*, not the size of the input `nodeIds` array sent to the database. [5](#0-4) 

**Why existing checks fail:** The `limit` cap at 25 is irrelevant to the attack — it controls result set size, not the cost of evaluating `abe.node_id = any(:nodeIds)` against a large array. Spring Boot's default Tomcat `max-parameter-count` is 10,000, so up to ~10,000 `node.id=eq:X` parameters are accepted. No middleware in `rest-java` enforces a `maxRepeatedQueryParameters` check equivalent to the Node.js `rest` module's `isRepeatedQueryParameterValidLength`. [6](#0-5) 

### Impact Explanation
An attacker flooding the endpoint with thousands of `node.id` equality parameters causes: (1) heap pressure from constructing large `HashSet` and `Long[]` objects per request; (2) JDBC parameter serialization overhead for large arrays; (3) PostgreSQL query planning overhead for large `ANY()` arrays. Under concurrent attack, this exhausts the DB connection pool and thread pool, making the `/api/v1/network/nodes` endpoint unavailable to legitimate clients. Clients unable to retrieve verified node endpoints may fall back to unverified or cached stale node lists, indirectly enabling transaction routing to unverified nodes.

### Likelihood Explanation
No authentication is required. The endpoint is publicly accessible. The attack requires only a standard HTTP client sending a crafted GET request with repeated `node.id` parameters — trivially scriptable. It is repeatable at high frequency. The missing `@Size` constraint is an oversight clearly visible by comparison with `RegisteredNodesRequest`.

### Recommendation
Add `@Size(max = N)` to `NetworkNodeRequest.nodeIds`, consistent with the pattern already used in `RegisteredNodesRequest`:

```java
@RestJavaQueryParam(name = NODE_ID, required = false)
@Builder.Default
@Size(max = 25)  // or a smaller reasonable bound
private List<NumberRangeParameter> nodeIds = List.of();
```

Additionally, enforce validation in `NetworkServiceImpl.getNetworkNodes()` as a defense-in-depth check, and consider adding a global repeated-parameter count filter in the `rest-java` filter chain analogous to the Node.js `rest` module's `maxRepeatedQueryParameters` guard.

### Proof of Concept
```bash
# Build a request with 5000 node.id equality parameters
PARAMS=$(python3 -c "print('&'.join(['node.id=' + str(i) for i in range(5000)]))")
curl -s "http://<mirror-node-host>/api/v1/network/nodes?$PARAMS" -o /dev/null -w "%{time_total}\n"

# Flood concurrently to exhaust DB connection pool
for i in $(seq 1 50); do
  curl -s "http://<mirror-node-host>/api/v1/network/nodes?$PARAMS" -o /dev/null &
done
wait

# Legitimate request now times out or returns 503
curl -v "http://<mirror-node-host>/api/v1/network/nodes"
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L30-31)
```java
    public static final int DEFAULT_LIMIT = 10;
    public static final int MAX_LIMIT = 25;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L36-38)
```java
    @RestJavaQueryParam(name = NODE_ID, required = false)
    @Builder.Default
    private List<NumberRangeParameter> nodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L41-44)
```java
    @Builder.Default
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L106-133)
```java
        final Set<Long> nodeIds = new HashSet<>();
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L96-96)
```java
            where (coalesce(array_length(:nodeIds, 1), 0) = 0 or abe.node_id = any(:nodeIds))
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L152-171)
```java
    @GetMapping("/nodes")
    ResponseEntity<NetworkNodesResponse> getNodes(@RequestParameter NetworkNodeRequest request) {
        final var fileId = request.getFileId();
        if (fileId != null && fileId.operator() != RangeOperator.EQ) {
            throw new IllegalArgumentException("Only equality operator is supported for file.id");
        }
        final var networkNodeRows = networkService.getNetworkNodes(request);
        final var limit = request.getEffectiveLimit();

        final var networkNodes = networkNodeMapper.map(networkNodeRows);

        final var sort = Sort.by(request.getOrder(), Constants.NODE_ID);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(networkNodes, pageable, NETWORK_NODE_EXTRACTOR);

        var response = new NetworkNodesResponse();
        response.setNodes(networkNodes);
        response.setLinks(links);
        return ResponseEntity.ok(response);
    }
```
