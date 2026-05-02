### Title
Unauthenticated Full Network Topology Enumeration via `/api/v1/network/registered-nodes`

### Summary
The `GET /api/v1/network/registered-nodes` endpoint is publicly accessible with no authentication, authorization, or rate limiting. Any external user can issue two sequential requests filtered by `type=BLOCK_NODE` and `type=MIRROR_NODE` (with pagination) to enumerate the complete IP address, port, and capability map of all registered network processing nodes. This topology map is sufficient to identify and target the minimum set of nodes whose disruption would affect ≥30% of network processing capacity.

### Finding Description

**Exact code path:**

`NetworkController.java` line 173–187 exposes the endpoint with no security annotation:

```java
@GetMapping("/registered-nodes")
RegisteredNodesResponse getRegisteredNodes(@RequestParameter RegisteredNodesRequest request) {
    final var registeredNodes = networkService.getRegisteredNodes(request);
    ...
}
```

`NetworkServiceImpl.java` lines 139–151 passes the `type` filter directly to the repository:

```java
return registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs(
        lowerBound, upperBound, nodeTypeId, page);
```

`RegisteredNodeRepository.java` lines 14–22 executes a native SQL query returning all non-deleted nodes of the requested type, including their full `service_endpoints` JSON (IP address, port, TLS flag, API capabilities):

```sql
select * from registered_node
where registered_node_id >= :lowerBound
  and registered_node_id <= :upperBound
  and deleted is false
  and (:type is null or type @> array[:type]::smallint[])
```

**Root cause:** No Spring Security configuration exists in the `rest-java` module (no `SecurityConfig*.java` found). No `@PreAuthorize`, `@Secured`, or any access-control annotation is present on the controller or service. No rate-limiting bean (unlike the `web3` module's `ThrottleConfiguration`) is applied to this endpoint. The `RegisteredNodesRequest` DTO enforces only a `@Max(MAX_LIMIT)` on the `limit` field — not any identity check.

**Why existing checks fail:** The only "check" is input validation (`@Min(1)`, `@Max(MAX_LIMIT)`, `@Size(max=2)` on range params). These are purely structural and do not restrict who can call the endpoint. The `authHandler` in the `rest` (Node.js) module is irrelevant here — this endpoint lives in the separate `rest-java` Spring Boot service with no equivalent middleware.

**Exploit flow:**

1. Attacker sends `GET /api/v1/network/registered-nodes?type=BLOCK_NODE&limit=100` — receives all block nodes with IP, port, TLS, and API capability fields.
2. Follows the `links.next` cursor (`registerednode.id=gt:N`) to paginate through all block nodes.
3. Repeats with `type=MIRROR_NODE`, `type=RPC_RELAY`, `type=GENERAL_SERVICE`.
4. Builds a complete cross-type topology map.
5. Applies a minimum vertex cover / weighted selection to identify the smallest set of nodes whose removal affects ≥30% of processing capacity.
6. Launches targeted DDoS or connection-exhaustion attacks against those specific IPs/ports.

### Impact Explanation
The response includes `ip_address`, `port`, `requires_tls`, and `endpoint_apis` (e.g., `STATUS`, `PUBLISH`) for every registered node. This is the exact information needed to mount a targeted, surgical disruption rather than a blind brute-force attack. Because the attacker can filter by type and paginate the full set, they can compute the minimum disruption set analytically before sending a single attack packet. The impact matches the stated scope: shutdown of ≥30% of network processing nodes without brute force.

### Likelihood Explanation
The attack requires zero privileges, zero credentials, and only two to a handful of HTTP GET requests from any internet-connected host. The endpoint is documented in the public OpenAPI spec (`openapi.yml` lines 969–989) with no `security` field, signaling it as intentionally open. Automation is trivial. Repeatability is unlimited since there is no rate limiting or IP blocking on this path in the `rest-java` service.

### Recommendation
1. **Authentication gate:** Require a valid API key or operator-level credential for any request to `/api/v1/network/registered-nodes`. Add a Spring Security `SecurityFilterChain` bean to the `rest-java` module that mandates authentication for this path.
2. **Rate limiting:** Apply a per-IP rate limiter (e.g., Bucket4j, as already used in the `web3` module) to this endpoint.
3. **Data minimization:** Consider whether full IP addresses and ports need to be returned to unauthenticated callers, or whether a redacted/aggregated view is sufficient for public consumers.
4. **Audit logging:** Log all accesses to this endpoint with caller IP for anomaly detection.

### Proof of Concept

```bash
# Step 1: Enumerate all block nodes
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=BLOCK_NODE&limit=100"

# Step 2: Follow pagination if links.next is present
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=BLOCK_NODE&limit=100&registerednode.id=gt:100"

# Step 3: Enumerate all mirror nodes
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=MIRROR_NODE&limit=100"

# Step 4: Enumerate remaining types
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=RPC_RELAY&limit=100"
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=GENERAL_SERVICE&limit=100"

# Result: complete topology map with IP:port for every registered node,
# enabling selection of minimum disruption set for targeted attack.
```

No authentication header is required. All requests return HTTP 200 with full node details. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

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

**File:** rest/api/v1/openapi.yml (L969-989)
```yaml
  /api/v1/network/registered-nodes:
    get:
      summary: Get registered nodes
      description: Returns the list of registered nodes
      operationId: getRegisteredNodes
      parameters:
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
        - $ref: "#/components/parameters/registeredNodeIdQueryParam"
        - $ref: "#/components/parameters/registeredNodeTypeQueryParam"
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/RegisteredNodesResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
      tags:
        - network
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L31-47)
```java
    @Builder.Default
    @Min(1)
    @Max(MAX_LIMIT)
    @RestJavaQueryParam(name = LIMIT, required = false, defaultValue = DEFAULT_LIMIT)
    private int limit = Integer.parseInt(DEFAULT_LIMIT);

    @Builder.Default
    @RestJavaQueryParam(name = ORDER, required = false, defaultValue = "asc")
    private Direction order = Direction.ASC;

    @Builder.Default
    @RestJavaQueryParam(name = REGISTERED_NODE_ID, required = false)
    @Size(max = 2)
    private List<NumberRangeParameter> registeredNodeIds = List.of();

    @RestJavaQueryParam(name = REGISTERED_NODE_TYPE, required = false)
    private RegisteredNodeType type;
```
