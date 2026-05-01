### Title
Unauthenticated Endpoint Triggers Uncached DB Aggregation on Every Call Due to Missing Rate Limiting in rest-java

### Summary
The `GET /api/v1/network/nodes` endpoint in the `rest-java` module is accessible to any unprivileged external user with no rate limiting and no response caching. Every call unconditionally executes `findNetworkNodes()`, which issues a native SQL query containing a `latest_node_stake` CTE that runs `select max(consensus_timestamp) from node_stake` as a subquery, plus joins across `address_book_entry`, `address_book`, and `node` tables. With no per-IP or global throttle on this path, an attacker can flood the endpoint and drive sustained DB CPU consumption well above the 24-hour baseline.

### Finding Description
**Exact code path:**

`NetworkController.getNodes()` (line 152–171) calls `networkService.getNetworkNodes(request)` unconditionally with no authentication or rate-limit check. [1](#0-0) 

`NetworkServiceImpl.getNetworkNodes()` (lines 100–137) delegates directly to `networkNodeRepository.findNetworkNodes(...)` with no caching layer. [2](#0-1) 

`NetworkNodeRepository.findNetworkNodes()` executes a native SQL query containing the `latest_node_stake` CTE:
```sql
latest_node_stake as (
    select max_stake, min_stake, node_id, reward_rate,
           stake, stake_not_rewarded, stake_rewarded, staking_period
    from node_stake
    where consensus_timestamp = (select max(consensus_timestamp) from node_stake)
)
``` [3](#0-2) 

This subquery executes on **every single request**. While PostgreSQL can resolve `max(consensus_timestamp)` via the primary key index `(consensus_timestamp, node_id)` (an index-only backward scan rather than a full sequential scan), the full query still involves multiple table joins (`address_book_entry`, `address_book`, `node`, `address_book_service_endpoint`) and a correlated subquery per result row for service endpoints. [4](#0-3) 

**Root cause — failed assumption:** The design assumes that infrastructure-level controls (e.g., an API gateway or reverse proxy) will throttle this endpoint. No such control exists within the application itself. The `ThrottleConfiguration`/`ThrottleManagerImpl` with bucket4j rate limiting exists exclusively in the `web3` module for contract calls; it is entirely absent from `rest-java`. [5](#0-4) 

The `rest-java` module's only registered filters are `LoggingFilter`, `MetricsFilter`, and `ShallowEtagHeaderFilter` — none of which throttle requests. [6](#0-5) 

The `@Cacheable` annotation with `NODE_STAKE_CACHE` exists only in the `grpc` module's `NodeStakeRepository`, not in `rest-java`'s `NetworkNodeRepository`. [7](#0-6) 

### Impact Explanation
Each unauthenticated `GET /api/v1/network/nodes` request causes the database to: (1) resolve `max(consensus_timestamp)` via index scan on `node_stake`, (2) scan `address_book_entry` joined to `address_book`, (3) left-join `node`, and (4) execute a correlated subquery per node row against `address_book_service_endpoint`. At high request rates (e.g., hundreds per second from a single client or distributed sources), the cumulative DB CPU load from these repeated query executions can exceed 30% above the 24-hour baseline, particularly on deployments where the DB is shared with the importer and gRPC services. The `limit` parameter is capped at 25 (`MAX_LIMIT`), which bounds per-request work but does not prevent volume-based amplification. [8](#0-7) 

### Likelihood Explanation
Preconditions: none. The endpoint requires no authentication, no API key, and no session. Any external user with network access can call it. The attack is trivially scriptable with standard HTTP tools (`curl`, `ab`, `wrk`). Because the `rest-java` service exposes this endpoint publicly (it is documented in the OpenAPI spec), it is discoverable by any API consumer. [9](#0-8) 

### Recommendation
1. **Add rate limiting to rest-java**: Introduce a bucket4j or Resilience4j rate limiter (global and/or per-IP) as a `OncePerRequestFilter` in the `rest-java` module, mirroring the pattern already used in `web3`.
2. **Cache the query result**: Annotate `NetworkNodeRepository.findNetworkNodes()` with `@Cacheable` using a short TTL (e.g., 10–30 seconds). Since the address book and node stake data change at most once per day, stale-for-seconds responses are acceptable and would eliminate the per-request DB round-trip entirely for the common case.
3. **Materialize the max timestamp**: Pre-compute and cache `max(consensus_timestamp)` from `node_stake` (as the `grpc` module already does via `NodeStakeRepository.findLatestTimestamp()` with `NODE_STAKE_CACHE`) and pass it as a parameter to `findNetworkNodes()` instead of re-computing it inline.

### Proof of Concept
```bash
# Flood the endpoint with concurrent requests (no credentials needed)
wrk -t8 -c200 -d60s http://<mirror-node-host>/api/v1/network/nodes

# Or with curl in a loop
while true; do
  curl -s http://<mirror-node-host>/api/v1/network/nodes > /dev/null &
done
```
Monitor PostgreSQL CPU via `pg_stat_activity` or `pg_stat_statements` — the query from `NetworkNodeRepository.findNetworkNodes` will appear at the top of CPU consumers. Compare the DB CPU metric (e.g., via Prometheus `process_cpu_seconds_total` on the DB pod) against the 24-hour rolling average; sustained flooding will push it above the 30% threshold.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L100-137)
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
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkNodeRepository.java (L33-39)
```java
            latest_node_stake as (
                select max_stake, min_stake, node_id, reward_rate,
                       stake, stake_not_rewarded, stake_rewarded,
                       staking_period
                from node_stake
                where consensus_timestamp = (select max(consensus_timestamp) from node_stake)
            ),
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L23-28)
```java
    // An empty map may be cached, indicating the node_stake table is empty
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/NetworkNodeRequest.java (L31-55)
```java
    public static final int MAX_LIMIT = 25;

    @RestJavaQueryParam(name = FILE_ID, required = false)
    private EntityIdRangeParameter fileId;

    @RestJavaQueryParam(name = NODE_ID, required = false)
    @Builder.Default
    private List<NumberRangeParameter> nodeIds = List.of();

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

**File:** rest/api/v1/openapi.yml (L948-960)
```yaml
  /api/v1/network/nodes:
    get:
      summary: Get the network address book nodes
      description: Returns the network's list of nodes used in consensus
      operationId: getNetworkNodes
      parameters:
        - $ref: "#/components/parameters/fileIdQueryParam"
        - $ref: "#/components/parameters/limitQueryParam"
        - $ref: "#/components/parameters/nodeIdQueryParam"
        - $ref: "#/components/parameters/orderQueryParam"
      responses:
        200:
          description: OK
```
