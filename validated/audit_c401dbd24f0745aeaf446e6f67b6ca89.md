All code references have been verified against the actual source. Here is the result:

---

# Audit Report

## Title
Unauthenticated Connection Pool Exhaustion DoS on `/api/v1/network/registered-nodes` via Absent Rate Limiting in rest-java

## Summary
The `GET /api/v1/network/registered-nodes` endpoint in the `rest-java` service has no application-level rate limiting. Each request acquires a HikariCP database connection to execute a native SQL query. An unauthenticated attacker flooding this endpoint with concurrent requests can exhaust the finite connection pool, causing all subsequent database-backed requests to fail with connection timeout errors.

## Finding Description

**Verified code path:**

`NetworkController.getRegisteredNodes()` at lines 173–187 calls `NetworkService.getRegisteredNodes(request)`, which delegates to `NetworkServiceImpl.getRegisteredNodes()` at lines 139–152. That method calls `registeredNodeRepository.findByRegisteredNodeIdBetweenAndDeletedIsFalseAndTypeIs()` at lines 21–22, executing a native SQL query that holds a HikariCP connection for the full query duration. [1](#0-0) [2](#0-1) [3](#0-2) 

**No rate limiting in rest-java — confirmed:**

A search across all `rest-java/**/*.java` files for `rateLimit`, `RateLimit`, `bucket4j`, and `ThrottleManager` returns zero matches. By contrast, the `web3` module has a full throttle stack (`ThrottleConfiguration` with bucket4j `rateLimitBucket`, `gasLimitBucket`, `opcodeRateLimitBucket`). [4](#0-3) 

`RestJavaConfiguration` registers only a `ShallowEtagHeaderFilter` and a `ProtobufHttpMessageConverter` — no rate-limiting filter. [5](#0-4) 

**HikariCP pool — confirmed:**

`CommonConfiguration` creates a `HikariDataSource` bound to `spring.datasource.hikari` properties. No `maximumPoolSize` is set in the rest-java Helm chart values (`config: {}`), so HikariCP defaults to 10 connections. [6](#0-5) [7](#0-6) 

The Prometheus alert fires at 75% pool utilization, confirming the pool is small and finite: [8](#0-7) 

**Request parameters provide no concurrency protection — confirmed:**

`RegisteredNodesRequest` enforces `@Max(MAX_LIMIT)` on `limit` (bounding result set size per request) but places no constraint on request concurrency or frequency. The `registeredNodeIds` field defaults to an empty list, causing `resolveRegisteredNodeIdBounds()` to use `lowerBound = 0L` and `upperBound = Long.MAX_VALUE`, triggering a full table scan on every default request. [9](#0-8) [10](#0-9) 

**Why existing mitigations are insufficient — confirmed:**

The GCP backend policy sets `maxRatePerEndpoint: 250`, but this is a load-balancing hint for GCP's backend service, not a hard per-IP or global rate limit enforced at the application layer. Additionally, `global.gateway.enabled` defaults to `false`, meaning the GCP gateway is not active in all deployments. [11](#0-10) [12](#0-11) 

## Impact Explanation
With the HikariCP pool exhausted (default: 10 connections), all database-backed requests to the mirror node — not just `/registered-nodes` — begin failing with `SQLTransientConnectionException` (HikariCP `connectionTimeout` default: 30 s). Registered nodes (block nodes, mirror nodes, RPC relays) polling this endpoint for peer discovery receive errors and cannot obtain updated service endpoint information. The impact is a targeted availability disruption of the entire rest-java service, not just the attacked endpoint.

## Likelihood Explanation
The attack requires zero authentication, zero special knowledge, and zero privileged access. A single attacker with ~10–20 concurrent connections is sufficient to saturate a 10-connection HikariCP pool. The attack is trivially scriptable with standard tools (`ab`, `wrk`, `hey`) and can be sustained indefinitely. The endpoint is publicly accessible and documented.

## Recommendation
1. **Application-level rate limiting:** Integrate bucket4j (already a dependency in `web3`) into `rest-java` by adding a `ThrottleConfiguration` and a servlet filter analogous to `web3`'s `ThrottleManagerImpl`, enforcing per-IP and/or global request-rate limits on all endpoints.
2. **Explicit HikariCP pool sizing:** Set `spring.datasource.hikari.maximumPoolSize` to a value appropriate for the expected concurrency in the rest-java application configuration, rather than relying on the HikariCP default of 10.
3. **Connection timeout tuning:** Reduce `spring.datasource.hikari.connectionTimeout` from the 30 s default to fail fast under pool exhaustion rather than queuing Tomcat threads.
4. **Infrastructure hardening:** Ensure `global.gateway.enabled: true` and the GCP backend policy is active in all production deployments, and consider supplementing it with a proper WAF rate-limiting rule.

## Proof of Concept
```bash
# Exhaust the default 10-connection HikariCP pool with 20 concurrent requests
wrk -t20 -c20 -d60s \
  "https://<mirror-node-host>/api/v1/network/registered-nodes"

# Observe subsequent requests failing with connection pool timeout:
curl "https://<mirror-node-host>/api/v1/network/registered-nodes"
# Expected: HTTP 500 / SQLTransientConnectionException after pool exhaustion
```

The default `lowerBound=0` / `upperBound=Long.MAX_VALUE` in `resolveRegisteredNodeIdBounds()` ensures each request performs a full table scan, maximizing connection hold time and making pool exhaustion easier to achieve. [13](#0-12)

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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L16-55)
```java
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

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-64)
```java
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L31-31)
```yaml
config: {}
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L49-61)
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
    healthCheckPolicy:
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L96-103)
```yaml
global:
  config: {}
  env: {}
  gateway:
    enabled: false
    hostnames: []
  image: {}
  middleware: false
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-221)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/dto/RegisteredNodesRequest.java (L31-35)
```java
    @Builder.Default
    @Min(1)
    @Max(MAX_LIMIT)
    @RestJavaQueryParam(name = LIMIT, required = false, defaultValue = DEFAULT_LIMIT)
    private int limit = Integer.parseInt(DEFAULT_LIMIT);
```
