### Title
Unauthenticated, Uncached, Unthrottled `GET /api/v1/network/stake` Enables Database Connection Pool Exhaustion via Sustained Flood

### Summary
The `GET /api/v1/network/stake` endpoint is publicly accessible with no authentication, no rate limiting, and no response caching in the `rest-java` module. Every request causes `NetworkStakeRepository.findLatest()` to execute a correlated subquery against the database. Under a sustained concurrent flood, all HikariCP connections can be held simultaneously, starving every other endpoint that shares the same pool.

### Finding Description
**Exact code path:**

`NetworkController.getNetworkStake()` (line 126–130) calls `networkService.getLatestNetworkStake()` with no guards. [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (lines 52–55) delegates directly to the repository with no caching layer. [2](#0-1) 

`NetworkStakeRepository.findLatest()` (lines 12–19) issues a native SQL query with a correlated `MAX` subquery on every invocation. [3](#0-2) 

**Root cause — three absent controls:**

1. **No rate limiting.** The `ThrottleConfiguration`/`ThrottleManagerImpl` bucket-based throttle exists only in the `web3` module and is wired exclusively to contract-call endpoints. No equivalent exists in `rest-java`. [4](#0-3) 

2. **No caching.** A grep across all `rest-java` Java sources for `@Cacheable`, `@Cache`, or `CacheManager` returns zero hits in the service/repository layer for this path. The only cache-adjacent mechanism is `ShallowEtagHeaderFilter` (registered for `/api/*`), which only suppresses response bodies on conditional `If-None-Match` GET requests — it does not prevent the database query from executing. [5](#0-4) 

3. **No authentication.** The OpenAPI spec declares no security scheme on `GET /api/v1/network/stake`, and the controller carries no Spring Security annotation. [6](#0-5) 

**Pool mechanics:** `CommonConfiguration` creates a `HikariDataSource` whose pool size is governed by `spring.datasource.hikari` properties. HikariCP's default `maximumPoolSize` is 10. Spring MVC (Tomcat) defaults to 200 worker threads. When ≥10 concurrent requests are in-flight and each holds a connection (even briefly), all remaining concurrent requests queue for a connection. Under a sustained flood the queue never drains, causing `SQLTransientConnectionException` (HikariCP connection timeout) for every other endpoint sharing the pool. [7](#0-6) 

### Impact Explanation
Any endpoint in `rest-java` that requires a database connection — supply, nodes, exchange rate, fees, schedules, etc. — will begin throwing connection-timeout errors while the pool is saturated. The Grafana alert `RestJavaHighDBConnections` fires at 75% pool utilization, confirming the operational team recognizes this as a critical resource boundary. [8](#0-7) 

### Likelihood Explanation
No special privileges, tokens, or accounts are required. A single attacker with a modest machine can sustain thousands of concurrent HTTP/1.1 keep-alive connections using standard tools (`wrk`, `ab`, `hey`). The endpoint accepts no parameters, so no input crafting is needed. The attack is trivially repeatable and scriptable.

### Recommendation
Apply at least one of the following, ideally in combination:

1. **In-process caching:** Annotate `NetworkServiceImpl.getLatestNetworkStake()` with `@Cacheable` (Spring Cache + Caffeine) with a TTL matching the staking-period update frequency (~24 h). This reduces DB calls to near-zero regardless of request rate.
2. **Rate limiting:** Port the `bucket4j`-based `ThrottleConfiguration` pattern from `web3` into `rest-java` and apply a per-IP or global request-per-second limit to `/api/v1/network/stake`.
3. **HTTP-layer caching:** Set a `Cache-Control: public, max-age=86400` response header for this endpoint so reverse proxies and CDNs absorb repeated requests before they reach the application.
4. **Connection pool sizing + timeout tuning:** Set an explicit `connectionTimeout` and `maximumPoolSize` in `spring.datasource.hikari` appropriate for the expected concurrency, and configure a short `statement-timeout` at the PostgreSQL level to bound query duration.

### Proof of Concept
```bash
# Flood with 50 concurrent workers, 100 000 total requests
wrk -t 50 -c 50 -d 60s https://<mirror-node-host>/api/v1/network/stake

# Simultaneously observe connection pool saturation
# (Prometheus / Grafana: hikaricp_connections_active / hikaricp_connections_max > 0.75)

# Observe other endpoints begin returning 500 / connection-timeout errors:
curl https://<mirror-node-host>/api/v1/network/supply
# → 500 Internal Server Error: Unable to acquire JDBC Connection
```

Preconditions: network access to the public REST-Java endpoint. No credentials required.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest/api/v1/openapi.yml (L990-1009)
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
        - network
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-222)
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
