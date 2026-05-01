### Title
Unauthenticated Endpoint `/api/v1/network/nodes` Lacks Rate Limiting, Enabling DB Connection Pool Exhaustion via Concurrent Request Flooding

### Summary
The `GET /api/v1/network/nodes` endpoint in the `rest-java` module has no rate limiting at the application layer. While `getEffectiveLimit()` caps result size at 25 rows, it does not restrict request frequency. An unprivileged attacker can flood the endpoint with concurrent requests, each executing a complex multi-CTE SQL query with a correlated subquery, exhausting the HikariCP connection pool and denying node discovery to legitimate users.

### Finding Description

**Code path:**

`NetworkController.java:152-171` → `NetworkServiceImpl.java:100-137` → `NetworkNodeRepository.findNetworkNodes()` (lines 25-105)

**Root cause — no rate limiting in rest-java:**

`NetworkController.getNodes()` has no throttle annotation, no rate-limit interceptor, and no Spring Security rate-limiting applied: [1](#0-0) 

The only filters present in the `rest-java` module are `LoggingFilter.java` and `MetricsFilter.java` — neither enforces rate limits. The throttle mechanism (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module and is not wired into `rest-java`.

**Failed assumption — `MAX_LIMIT` cap prevents abuse:**

`getEffectiveLimit()` caps the SQL `LIMIT` clause at 25: [2](#0-1) 

The `limit` field only has `@Min(1)` — no `@Max` constraint — so `Integer.MAX_VALUE` passes bean validation: [3](#0-2) 

This cap controls result-set size, not request frequency. Each request still acquires a DB connection and executes the full query.

**Query cost per request:**

Each call to `findNetworkNodes()` executes a 3-CTE query joining `address_book`, `address_book_entry`, `node_stake`, and `node`, plus a **correlated subquery** per returned row against `address_book_service_endpoint`: [4](#0-3) 

**Service call passes the capped limit directly to the repository:** [5](#0-4) 

### Impact Explanation

With no rate limiting, an attacker sending N concurrent requests holds N HikariCP connections simultaneously, each executing the multi-CTE query. Once the pool is exhausted, all subsequent requests — including those from legitimate transaction submitters needing node discovery — block waiting for a connection or fail with a timeout. This is a complete, unauthenticated denial-of-service against the node-discovery API, which is critical for clients to know which nodes to submit transactions to.

### Likelihood Explanation

No authentication or API key is required. The endpoint is publicly reachable at `GET /api/v1/network/nodes`. A single attacker with a modest number of concurrent HTTP connections (matching or exceeding the HikariCP pool size, typically 10 by default in Spring Boot) can trigger the condition. The attack is trivially repeatable with standard tools (`ab`, `wrk`, `curl` in parallel). No special knowledge of the protocol is needed beyond the public API path.

### Recommendation

1. **Add application-layer rate limiting** to the `rest-java` module for the `/api/v1/network/nodes` endpoint, mirroring the `bucket4j`-based `ThrottleConfiguration` already present in `web3`. Apply it as a servlet filter or Spring MVC interceptor scoped to `rest-java`.
2. **Add `@Max(25)` to `NetworkNodeRequest.limit`** so bean validation rejects out-of-range values before they reach the service layer, rather than silently capping them:
   ```java
   @Min(1)
   @Max(MAX_LIMIT)
   private int limit = DEFAULT_LIMIT;
   ```
3. **Configure HikariCP connection timeout** to fail fast rather than queue indefinitely, limiting blast radius.
4. **Deploy infrastructure-level rate limiting** (e.g., nginx `limit_req`, API gateway throttling) as a defense-in-depth layer.

### Proof of Concept

```bash
# Flood the endpoint with 200 concurrent requests (exceeds default HikariCP pool of 10)
# No authentication required
seq 200 | xargs -P 200 -I{} curl -s \
  "https://<mirror-node-host>/api/v1/network/nodes?limit=25" \
  -o /dev/null -w "%{http_code}\n"

# Legitimate request issued concurrently — will block or timeout:
curl -v "https://<mirror-node-host>/api/v1/network/nodes"
# Expected: connection timeout or HTTP 500 due to pool exhaustion
```

Preconditions: network access to the `rest-java` service; no credentials needed.
Trigger: concurrent requests saturate HikariCP pool.
Result: legitimate node-discovery requests fail; transaction submitters cannot determine which nodes to target.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L40-43)
```java
    @RestJavaQueryParam(name = LIMIT, required = false)
    @Builder.Default
    @Min(1)
    private int limit = DEFAULT_LIMIT;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L53-55)
```java
    public int getEffectiveLimit() {
        return Math.min(limit, MAX_LIMIT);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L72-83)
```java
                coalesce((
                    select jsonb_agg(
                        jsonb_build_object(
                            'domain_name', coalesce(abse.domain_name, ''),
                            'ip_address_v4', coalesce(abse.ip_address_v4, ''),
                            'port', abse.port
                        ) order by abse.ip_address_v4 asc, abse.port asc
                    )
                    from address_book_service_endpoint abse
                    where abse.consensus_timestamp = abe.consensus_timestamp
                      and abse.node_id = abe.node_id
                ), '[]'::jsonb)::text as serviceEndpointsJson,
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L100-136)
```java
    public List<NetworkNodeDto> getNetworkNodes(NetworkNodeRequest request) {
        final long fileId = getAddressBookFileId(request);
        final var limit = request.getEffectiveLimit();
        final var nodeIdParams = request.getNodeIds();
        final var orderDirection = request.getOrder().name();

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

        return networkNodeRepository.findNetworkNodes(
                fileId, nodeIdArray, lowerBound, upperBound, orderDirection, limit);
```
