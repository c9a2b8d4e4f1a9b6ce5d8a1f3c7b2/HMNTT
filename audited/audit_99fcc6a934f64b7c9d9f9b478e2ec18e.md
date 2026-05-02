### Title
Unauthenticated High-Frequency Flooding of `/api/v1/network/stake` Exhausts HikariCP Connection Pool in rest-java

### Summary
The `GET /api/v1/network/stake` endpoint in the rest-java service invokes `networkStakeRepository.findLatest()` on every request with no application-level rate limiting and no result caching. Because each call acquires a HikariCP connection to execute a native SQL query, a high-frequency flood from an unprivileged external attacker can exhaust the shared connection pool, causing all other rest-java endpoints to time out waiting for a connection and effectively taking the service offline.

### Finding Description
**Code path:**

`NetworkController.getNetworkStake()` (line 127–130) calls `networkService.getLatestNetworkStake()` with no throttle guard. [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56) directly delegates to the repository with no caching annotation. [2](#0-1) 

`NetworkStakeRepository.findLatest()` executes a native correlated subquery (`SELECT * FROM network_stake WHERE consensus_timestamp = (SELECT MAX(...) FROM network_stake)`) on every invocation — no `@Cacheable` is present. [3](#0-2) 

**Root cause — no rate limiting in rest-java:** The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` bucket4j infrastructure exists exclusively in the `web3` module. [4](#0-3) 

The rest-java `config/` package contains only `JacksonConfiguration`, `LoggingFilter`, `MetricsConfiguration`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, and `WebMvcConfiguration` — no throttle bean.


**Root cause — no caching:** Compare to the grpc module's `NodeStakeRepository`, which annotates its equivalent method with `@Cacheable`. The rest-java `NetworkStakeRepository.findLatest()` has no such annotation. [5](#0-4) 

**Connection pool:** The rest-java service uses HikariCP via `CommonConfiguration`, configured through `spring.datasource.hikari`. No explicit `maximumPoolSize` override is present in rest-java resources; HikariCP's default is **10 connections**. The monitoring alert fires only after >75% utilization sustained for 5 minutes — far too slow to prevent an active flood. [6](#0-5) [7](#0-6) 

### Impact Explanation
With a default pool of 10 connections and no rate limiting, an attacker sending ~50–100 concurrent requests/second to `GET /api/v1/network/stake` will hold all HikariCP connections busy. Every other rest-java endpoint (`/api/v1/network/nodes`, `/api/v1/network/supply`, `/api/v1/transactions`, etc.) will block at `HikariPool.getConnection()` until the configured `connectionTimeout` (default 30 s) elapses, returning 500 errors to all legitimate users. The entire rest-java service becomes unavailable for the duration of the attack.

### Likelihood Explanation
The endpoint requires no authentication, accepts no parameters, and is publicly documented in the OpenAPI spec. [8](#0-7) 

Any attacker with a basic HTTP flood tool (e.g., `wrk`, `ab`, `hey`) can trigger this with a single command. No credentials, tokens, or special knowledge are required. The attack is trivially repeatable and can be sustained indefinitely.

### Recommendation
Apply at least one of the following:

1. **Add `@Cacheable`** to `NetworkStakeRepository.findLatest()` (or in `NetworkServiceImpl.getLatestNetworkStake()`) with a short TTL (e.g., 30 s). Network stake data changes at most once per staking period (~24 h), making aggressive caching safe and effective.

2. **Add application-level rate limiting** to the rest-java module, mirroring the bucket4j `ThrottleConfiguration` already present in `web3`. Apply it as a servlet filter or Spring interceptor on all `/api/v1/network/*` endpoints.

3. **Enforce the GCP gateway `maxRatePerEndpoint`** (currently set to 250 but noted as requiring an HPA change to take effect) so the infrastructure layer rejects excess requests before they reach the application. [9](#0-8) 

### Proof of Concept
```bash
# Flood the endpoint with 200 concurrent connections, no auth required
wrk -t 20 -c 200 -d 60s http://<mirror-node-host>/api/v1/network/stake

# Simultaneously verify other endpoints are starved:
curl -w "%{http_code} %{time_total}s\n" http://<mirror-node-host>/api/v1/network/supply
# Expected: 500 or connection timeout after ~30s once pool is exhausted
```

Preconditions: Public network access to the rest-java service. No credentials needed.
Trigger: Sustained concurrent GET requests to `/api/v1/network/stake` exceeding the HikariCP pool size.
Result: All rest-java endpoints return errors; legitimate traffic is fully blocked for the attack duration.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L52-56)
```java
    public NetworkStake getLatestNetworkStake() {
        return networkStakeRepository
                .findLatest()
                .orElseThrow(() -> new EntityNotFoundException("No network stake data found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NetworkStakeRepository.java (L12-19)
```java
    @Query(value = """
        select *
        from network_stake
        where consensus_timestamp = (
            select max(consensus_timestamp) from network_stake
        )
        """, nativeQuery = true)
    Optional<NetworkStake> findLatest();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L23-28)
```java
    // An empty map may be cached, indicating the node_stake table is empty
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L60-95)
```java
    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @Lazy
    DataSource dataSource(
            DataSourceProperties dataSourceProperties,
            HikariConfig hikariConfig,
            DatabaseWaiter databaseWaiter,
            ObjectProvider<JdbcConnectionDetails> detailsProvider) {

        var jdbcUrl = dataSourceProperties.determineUrl();
        var username = dataSourceProperties.determineUsername();
        var password = dataSourceProperties.determinePassword();

        final var connectionDetails = detailsProvider.getIfAvailable();
        if (connectionDetails != null) {
            jdbcUrl = connectionDetails.getJdbcUrl();
            username = connectionDetails.getUsername();
            password = connectionDetails.getPassword();
        }

        databaseWaiter.waitForDatabase(jdbcUrl, username, password);

        final var config = new HikariConfig();
        hikariConfig.copyStateTo(config);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);

        return new HikariDataSource(config);
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
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

**File:** rest/api/v1/openapi.yml (L990-1008)
```yaml
  /api/v1/network/stake:
    get:
      summary: Get network stake information
      description: Returns the network's current stake information.
      operationId: getNetworkStake
      responses:
        200:
          description: OK
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/NetworkStakeResponse"
        400:
          $ref: "#/components/responses/InvalidParameterError"
        404:
          $ref: "#/components/responses/NetworkStakeNotFound"
        500:
          $ref: "#/components/responses/ServiceUnavailableError"
      tags:
```
