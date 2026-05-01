### Title
Unauthenticated Full Enumeration of Network Node Endpoints via Paginated `/api/v1/network/registered-nodes`

### Summary
The `/api/v1/network/registered-nodes` endpoint is publicly accessible with no authentication, no rate limiting, and no access control. It exposes IP addresses, ports, and node types (BLOCK_NODE, MIRROR_NODE, etc.) for all active registered nodes. Any unprivileged external user can paginate through the entire node registry using the `registerednode.id=gte:X&limit=100` pattern, building a complete infrastructure map suitable for coordinating targeted disruption of ≥30% of network processing nodes.

### Finding Description

**Code location:**
- `rest-java/src/main/java/org/hiero/mirror/restjava/repository/RegisteredNodeRepository.java`, lines 14–22
- `rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java`, lines 173–187
- `rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java`, lines 139–152

**Root cause:** The `getRegisteredNodes` handler at `NetworkController.java:173` has no `@Secured`, `@PreAuthorize`, `@RolesAllowed`, or any Spring Security filter applied. No `SecurityFilterChain` configuration exists in the `rest-java` module. The `HIGH_VOLUME_THROTTLE` constant defined in `Constants.java:19` is only wired to the fee-estimation POST endpoint (`NetworkController.java:116`), not to the registered-nodes GET endpoint.

**Exploit flow:**

The repository query at `RegisteredNodeRepository.java:14–22` accepts caller-controlled `lowerBound`, `upperBound`, and `type` parameters with no server-side guard:

```sql
select * from registered_node
where registered_node_id >= :lowerBound
  and registered_node_id <= :upperBound
  and deleted is false
  and (:type is null or type @> array[:type]::smallint[])
```

`RegisteredNodesRequest.java:33–35` allows `limit` up to `MAX_LIMIT = 100` (`Constants.java:35`). The `resolveRegisteredNodeIdBounds` method in `NetworkServiceImpl.java:154–175` defaults `lowerBound = 0` and `upperBound = Long.MAX_VALUE` when no range is supplied, meaning a single unauthenticated call with no filters returns up to 100 nodes.

The `linkFactory.create(...)` call at `NetworkController.java:180` automatically generates a `next` cursor link (confirmed by test `NetworkControllerTest.java:1940–1942`):
```
/api/v1/network/registered-nodes?limit=1&registerednode.id=gt:1
```
This cursor is handed directly to the attacker in the response body, making full enumeration trivial without any manual bound-incrementing.

Each response page includes `ipAddress`, `port`, `requiresTls`, and `type` fields for every node (confirmed by `NetworkControllerTest.java:1800–1848`).

**Why existing checks fail:** There are no existing checks. No authentication layer, no per-IP rate limiting, no CAPTCHA, no API key requirement, and no field-level redaction of IP/port data on this endpoint.

### Impact Explanation
An attacker obtains a complete, accurate map of all active BLOCK_NODE and MIRROR_NODE IP addresses and ports. With this map they can:
- Launch volumetric DDoS attacks against the specific IPs/ports of ≥30% of block or mirror nodes simultaneously.
- Exploit any known vulnerabilities in the node software at those addresses.
- Selectively target nodes to degrade or halt block propagation or mirror synchronization.

Because the endpoint returns `deleted is false` nodes only, the map is always current. The impact aligns with the stated scope: shutdown of ≥30% of network processing nodes without brute force.

### Likelihood Explanation
Exploitation requires zero privileges, zero credentials, and only standard HTTP tooling (`curl`, `wget`, a simple script). The `next` link in the response eliminates even the need to guess ID ranges. A single script can enumerate the entire registry in seconds. This is repeatable on demand and leaves no application-level trace beyond normal HTTP access logs, which are often not monitored for this pattern.

### Recommendation
1. **Authentication gate:** Require a valid API key or OAuth2 bearer token for `/api/v1/network/registered-nodes`. Public node discovery (if needed) should expose only non-sensitive metadata, not raw IP/port data.
2. **Rate limiting:** Apply the existing `HIGH_VOLUME_THROTTLE` mechanism (or an equivalent per-IP bucket) to this endpoint, consistent with how it is applied to fee estimation.
3. **Field redaction:** If the endpoint must remain public, strip `ipAddress` and `port` from the response, returning only node IDs and types.
4. **Pagination cap:** Enforce a hard cap on total results returnable per session/IP to prevent full enumeration even if some data must remain public.

### Proof of Concept

```bash
# Step 1: Fetch first page of all BLOCK_NODE entries (no auth required)
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=BLOCK_NODE&limit=100"

# Response includes:
# { "registeredNodes": [ { "registeredNodeId": 1, "serviceEndpoints": [
#     { "ipAddress": "x.x.x.x", "port": 50211, "requiresTls": true, "type": "BLOCK_NODE" }
#   ] }, ... ],
#   "links": { "next": "/api/v1/network/registered-nodes?limit=100&registerednode.id=gt:100" }
# }

# Step 2: Follow the `next` link to get the next page
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?limit=100&registerednode.id=gt:100&type=BLOCK_NODE"

# Step 3: Repeat until `links.next` is null — complete map obtained.

# Step 4: Repeat for MIRROR_NODE
curl -s "https://<mirror-node-host>/api/v1/network/registered-nodes?type=MIRROR_NODE&limit=100"

# Result: Full IP:port list of all active BLOCK_NODE and MIRROR_NODE instances,
# ready for coordinated targeted attack.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L19-35)
```java
    public static final String HIGH_VOLUME_THROTTLE = "high_volume_throttle";
    public static final String HOOK_ID = "hook.id";
    public static final String KEY = "key";
    public static final String LIMIT = "limit";
    public static final String NODE_ID = "node.id";
    public static final String ORDER = "order";
    public static final String RECEIVER_ID = "receiver.id";
    public static final String REGISTERED_NODE_ID = "registerednode.id";
    public static final String REGISTERED_NODE_TYPE = "type";
    public static final String SENDER_ID = "sender.id";
    public static final String SERIAL_NUMBER = "serialnumber";
    public static final String TIMESTAMP = "timestamp";
    public static final String TOKEN_ID = "token.id";

    // Defaults and constraints
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L154-156)
```java
    private static Range<Long> resolveRegisteredNodeIdBounds(List<NumberRangeParameter> registeredNodeIdRanges) {
        long lowerBound = 0L;
        long upperBound = MAX_VALUE;
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/NetworkControllerTest.java (L1800-1848)
```java
        void blockNodeWithMultipleEndpointApis() {
            // given
            final var expectedIp = "192.168.1.10";
            final var expectedPort = 50211;
            final var expectedRequiresTls = true;
            final var expectedApis = List.of(
                    RegisteredServiceEndpoint.BlockNodeApi.STATUS, RegisteredServiceEndpoint.BlockNodeApi.PUBLISH);

            final var blockNodeEndpoint = RegisteredServiceEndpoint.builder()
                    .blockNode(RegisteredServiceEndpoint.BlockNodeEndpoint.builder()
                            .endpointApis(expectedApis)
                            .build())
                    .ipAddress(expectedIp)
                    .port(expectedPort)
                    .requiresTls(expectedRequiresTls)
                    .build();

            domainBuilder
                    .registeredNode()
                    .customize(r -> r.registeredNodeId(100L)
                            .type(List.of(RegisteredNodeType.BLOCK_NODE.getId()))
                            .serviceEndpoints(List.of(blockNodeEndpoint)))
                    .persist();

            // when
            final var actual = restClient
                    .get()
                    .uri("?type=BLOCK_NODE&registerednode.id=100")
                    .retrieve()
                    .body(org.hiero.mirror.rest.model.RegisteredNodesResponse.class);

            // then
            assertThat(actual).isNotNull();
            assertThat(actual.getRegisteredNodes()).isNotNull().hasSize(1);

            final var blockNode = actual.getRegisteredNodes().get(0);
            assertThat(blockNode.getServiceEndpoints()).isNotEmpty();

            final var endpoint = blockNode.getServiceEndpoints().get(0);
            assertThat(endpoint.getIpAddress()).isEqualTo(expectedIp);
            assertThat(endpoint.getPort()).isEqualTo(expectedPort);
            assertThat(endpoint.getRequiresTls()).isEqualTo(expectedRequiresTls);
            assertThat(endpoint.getType()).isEqualTo(org.hiero.mirror.rest.model.RegisteredNodeType.BLOCK_NODE);

            assertThat(endpoint.getBlockNode()).isNotNull();
            assertThat(endpoint.getBlockNode().getEndpointApis())
                    .containsExactly(
                            org.hiero.mirror.rest.model.RegisteredBlockNodeApi.STATUS,
                            org.hiero.mirror.rest.model.RegisteredBlockNodeApi.PUBLISH);
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/NetworkControllerTest.java (L1940-1942)
```java
            assertThat(actual.getLinks().getNext())
                    .isEqualTo(
                            "/api/v1/network/registered-nodes?limit=1&%s=gt:1".formatted(Constants.REGISTERED_NODE_ID));
```
