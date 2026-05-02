### Title
Unauthenticated `GET /api/v1/network/registered-nodes` Lacks Application-Level Rate Limiting, Enabling DB Connection Pool Exhaustion DoS

### Summary
The `GET /api/v1/network/registered-nodes` endpoint is publicly accessible with no authentication and no application-level rate limiting in the `rest-java` module. Every request unconditionally issues a native SQL query against the database via `findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()`, consuming a HikariCP connection for the query's duration. A high-volume flood of concurrent requests from an unprivileged attacker can exhaust the connection pool, causing all subsequent requests (including legitimate ones) to queue and time out.

### Finding Description

**Exact code path:**

`NetworkController.getRegisteredNodes()` at [1](#0-0)  calls `NetworkServiceImpl.getRegisteredNodes()` at [2](#0-1)  which unconditionally calls `registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()`.

The native SQL query is: [3](#0-2) 

**Root cause — no application-level rate limiting in rest-java:**

The only rate-limiting infrastructure in the codebase (bucket4j `ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` module and is wired only to contract-call endpoints: [4](#0-3) 

No equivalent throttle bean, filter, or interceptor exists anywhere in `rest-java`. There is no `WebSecurityConfig` or servlet filter applying per-IP or global rate limiting to `NetworkController`.

**Input validation is insufficient to prevent flooding:**

`RegisteredNodesRequest` caps `limit` at 100 and `registeredNodeIds` at 2 entries: [5](#0-4) 

These constraints bound the *result size* but do not limit *request rate*. An attacker sends many small, valid requests (e.g., `limit=1`) — each still acquires a DB connection.

**Connection pool:**

The `rest-java` module uses HikariCP configured via `spring.datasource.hikari`: [6](#0-5) 

No explicit `maximumPoolSize` override is present in `rest-java` resources (only `banner.txt` exists under `rest-java/src/main/resources/`), so HikariCP defaults apply (10 connections). The Grafana dashboard confirms the pool is monitored: [7](#0-6) 

**Infrastructure-level protection is optional and deployment-specific:**

The Helm chart defines a GCP backend policy with `maxRatePerEndpoint: 250`, but this is gated on `gcp.enabled: true`: [8](#0-7) 

Non-GCP deployments (bare-metal, AWS, Azure, local) have no equivalent protection. Even when enabled, this is a per-endpoint aggregate limit, not a per-IP limit, so a distributed attack from many IPs is not mitigated.

### Impact Explanation

When the HikariCP pool (default 10 connections) is saturated, all further requests block waiting for a free connection up to `connectionTimeout` (HikariCP default: 30 seconds), then throw `SQLTransientConnectionException`. This causes:
- All `GET /api/v1/network/registered-nodes` responses to fail with 500 errors for legitimate clients
- Potential spillover to other endpoints sharing the same pool (all rest-java endpoints share one `DataSource`)
- Gossip node discovery by legitimate network participants is disrupted

The `RestJavaHighDBConnections` alert fires only after 5 minutes at >75% utilization — well after the DoS is effective: [9](#0-8) 

### Likelihood Explanation

**Preconditions:** None. No account, API key, or authentication is required. The endpoint is publicly documented in the OpenAPI spec: [10](#0-9) 

**Feasibility:** A single attacker machine sending ~500–1000 concurrent HTTP/1.1 requests/second with `limit=1` is sufficient to keep the 10-connection pool saturated, given that even fast queries (sub-millisecond on a small `registered_node` table) require a connection acquisition round-trip. Tools like `wrk`, `ab`, or `hey` trivially achieve this. The attack is repeatable and stateless.

**Mitigating factor:** The `registered_node` table is expected to be small and the query uses an indexed range scan with `LIMIT`, so individual query duration is very short. This raises the request rate needed to sustain pool exhaustion, but does not eliminate the risk — especially under concurrent load from multiple sources or when the DB is already under load from other queries.

### Recommendation

1. **Add application-level rate limiting to `rest-java`**: Introduce a bucket4j or Resilience4j `RateLimiter` bean in `rest-java` analogous to the `web3` `ThrottleConfiguration`, applied via a `HandlerInterceptor` or Spring Security filter to all public endpoints, with per-IP granularity.

2. **Add a query-level statement timeout**: Configure `spring.datasource.hikari.connection-timeout` and a PostgreSQL `statement_timeout` for the rest-java datasource to bound the maximum connection hold time per query.

3. **Increase pool size or add connection queue limits**: Set an explicit `maximumPoolSize` appropriate for expected concurrency, and configure `connectionTimeout` to fail fast rather than queue indefinitely.

4. **Enforce per-IP rate limiting at the infrastructure layer unconditionally**: Do not rely solely on the optional GCP backend policy; add an NGINX/Envoy/ingress-level rate limit that applies regardless of cloud provider.

### Proof of Concept

```bash
# No authentication required. Flood with concurrent requests.
# Using 'hey' (https://github.com/rakyll/hey):

hey -n 100000 -c 500 -q 0 \
  "https://<mirror-node-host>/api/v1/network/registered-nodes?limit=1&registerednode.id=gte:0"

# Expected result:
# - First ~10 concurrent requests succeed (pool not yet exhausted)
# - Subsequent requests receive HTTP 500 with SQLTransientConnectionException
#   ("HikariPool-1 - Connection is not available, request timed out after 30000ms")
# - Legitimate clients querying the endpoint during the flood receive errors
# - All rest-java endpoints sharing the same HikariCP DataSource are also degraded
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L31-44)
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
```

**File:** charts/hedera-mirror-common/dashboards/hedera-mirror-rest-java.json (L1621-1641)
```json
            "uid": "${prometheus}"
          },
          "expr": "avg(hikaricp_connections_max{application=\"$application\",cluster=~\"$cluster\",namespace=~\"$namespace\",pod=~\"$pod\"})",
          "hide": false,
          "interval": "1m",
          "legendFormat": "max",
          "refId": "C"
        },
        {
          "datasource": {
            "uid": "${prometheus}"
          },
          "expr": "avg(hikaricp_connections_pending{application=\"$application\",cluster=~\"$cluster\",namespace=~\"$namespace\",pod=~\"$pod\"})",
          "hide": false,
          "interval": "1m",
          "legendFormat": "pending",
          "refId": "E"
        }
      ],
      "title": "Connection Pool",
      "type": "timeseries"
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L49-60)
```yaml
gateway:
  gcp:
    backendPolicy:
      connectionDraining:
        drainingTimeoutSec: 10
      logging:
        enabled: false
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
    enabled: true
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L203-210)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
```

**File:** rest/api/v1/openapi.yml (L969-988)
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
```
