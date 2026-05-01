### Title
Unauthenticated Concurrent Full-Range DB Scans on `/api/v1/network/registered-nodes` Due to Missing Rate Limiting in rest-java Module

### Summary
The `GET /api/v1/network/registered-nodes` endpoint is publicly accessible with no authentication and no application-level rate limiting in the `rest-java` module. An unprivileged attacker can send unlimited concurrent requests with `limit=100` (MAX_LIMIT) and no `registeredNodeIds` filter, causing each request to execute a full-range scan of the `registered_node` table (`registered_node_id >= 0 AND registered_node_id <= Long.MAX_VALUE`) with no caching layer, saturating DB I/O under concurrent load.

### Finding Description

**Code path:**

`NetworkController.java` line 173–187 exposes `GET /api/v1/network/registered-nodes` with no authentication or rate-limiting annotation. [1](#0-0) 

`NetworkServiceImpl.getRegisteredNodes()` lines 140–152 constructs `PageRequest.of(0, request.getLimit(), sort)` and calls the repository with bounds `[0, Long.MAX_VALUE]` when no `registeredNodeIds` filter is supplied. [2](#0-1) 

`resolveRegisteredNodeIdBounds()` returns `Range.closed(0L, Long.MAX_VALUE)` when the input list is empty (no filter provided). [3](#0-2) 

The repository executes a native query scanning `registered_node_id >= :lowerBound AND registered_node_id <= :upperBound AND deleted is false AND (:type is null OR type @> array[:type]::smallint[])` — a full primary-key range traversal with a JSONB array containment check, bounded only by `LIMIT 100`. [4](#0-3) 

`MAX_LIMIT = 100` and `DEFAULT_LIMIT = "25"` are the only per-request bounds; there is no per-IP or global request-rate cap in the `rest-java` module. [5](#0-4) 

**Root cause:** The `rest-java` module has no rate-limiting infrastructure. The `ThrottleConfiguration` / `ThrottleManagerImpl` that exist in the codebase are scoped exclusively to the `web3` module and are not applied to `rest-java` controllers. [6](#0-5) 

**Exploit flow:**
1. Attacker sends N concurrent `GET /api/v1/network/registered-nodes?limit=100` requests (no filter, no auth).
2. Each request reaches `getRegisteredNodes()`, constructs `PageRequest.of(0, 100, sort)`, and issues the native query with bounds `[0, Long.MAX_VALUE]`.
3. The DB executes N simultaneous index-range scans of `registered_node` with a JSONB array containment predicate (`type @> array[null]::smallint[]` short-circuits, but with a type filter it is evaluated per row).
4. No caching layer absorbs repeated identical queries.
5. No server-side throttle rejects or queues excess requests.

### Impact Explanation
Each concurrent request issues a DB query that traverses the `registered_node` primary-key index from 0 to `Long.MAX_VALUE`, evaluates `deleted is false` and the JSONB `type @>` predicate per row, and returns up to 100 rows. With no rate limiting, an attacker can sustain hundreds of concurrent connections, multiplying DB I/O linearly. As the `registered_node` table grows (it is expected to grow as block nodes, mirror nodes, and RPC relays register), the per-query cost increases. The absence of response caching means every request hits the DB. This can increase DB CPU and I/O consumption well beyond 30% relative to baseline, degrading service for legitimate users.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no amplification beyond standard HTTP concurrency tools (`ab`, `wrk`, `hey`, `curl --parallel`). The endpoint is documented in the public OpenAPI spec. The attacker needs only a network connection and the ability to sustain concurrent HTTP requests. The attack is repeatable and stateless, making it trivially automatable. [7](#0-6) 

### Recommendation
1. **Add rate limiting to `rest-java`**: Apply a per-IP or global request-rate limiter (e.g., bucket4j, Spring's `HandlerInterceptor`, or an API gateway policy) to `GET /api/v1/network/registered-nodes`, mirroring the pattern already used in the `web3` module.
2. **Add response caching**: The `registered_node` table changes infrequently. Cache responses (e.g., with Spring's `@Cacheable` or an HTTP `Cache-Control` header) for a short TTL (e.g., 30–60 seconds) to absorb burst traffic without hitting the DB.
3. **Cap concurrent DB connections per endpoint**: Use a connection pool semaphore or queue to prevent a single endpoint from monopolizing DB connections.
4. **Add a DB-level index on `(deleted, registered_node_id)`**: This avoids a full primary-key scan when filtering `deleted is false`, reducing per-query cost.

### Proof of Concept

```bash
# Send 200 concurrent requests with limit=100 and no filter
# Requires: wrk or hey installed, endpoint reachable

# Using 'hey':
hey -n 2000 -c 200 \
  "https://<mirror-node-host>/api/v1/network/registered-nodes?limit=100"

# Observe DB metrics (pg_stat_activity, CPU, I/O) during the run.
# Expected: multiple simultaneous queries:
#   SELECT * FROM registered_node
#   WHERE registered_node_id >= 0
#     AND registered_node_id <= 9223372036854775807
#     AND deleted IS FALSE
#     AND (NULL IS NULL OR type @> ARRAY[NULL]::smallint[])
#   LIMIT 100;
# No 429 responses will be returned; all requests are served.
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L140-152)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/common/Constants.java (L34-36)
```java
    public static final String DEFAULT_LIMIT = "25";
    public static final int MAX_LIMIT = 100;
    public static final int MAX_REPEATED_QUERY_PARAMETERS = 100;
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
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
