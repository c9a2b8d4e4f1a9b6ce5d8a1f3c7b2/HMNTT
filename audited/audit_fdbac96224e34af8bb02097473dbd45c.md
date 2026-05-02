### Title
Unauthenticated Connection Pool Exhaustion DoS on `/api/v1/accounts/{id}/airdrops/outstanding`

### Summary
The `rest-java` module exposes `GET /api/v1/accounts/{id}/airdrops/outstanding` with no rate limiting, no per-IP throttling, and no concurrency controls. Every request acquires a HikariCP database connection via `repository.findAll()`. An unprivileged attacker sending high-concurrency requests can exhaust the finite connection pool, causing all subsequent requests (from any user) to block until `connectionTimeout` is exceeded and then fail with `SQLTransientConnectionException`, effectively denying service to all users.

### Finding Description

**Code path:**

`TokenAirdropsController.getOutstandingAirdrops()` (line 67–75) builds a `TokenAirdropRequest` and calls `service.getAirdrops(request)` with no rate-limiting guard. [1](#0-0) 

`TokenAirdropServiceImpl.getAirdrops()` (lines 19–22) calls `entityService.lookup()` (which for numeric IDs does **not** hit the DB) and then unconditionally calls `repository.findAll(request, id)`. [2](#0-1) 

`TokenAirdropRepositoryCustomImpl.findAll()` (lines 58–72) executes a jOOQ `SELECT … FROM token_airdrop WHERE … LIMIT ?` query, holding a HikariCP connection for the full query duration. [3](#0-2) 

**Root cause — missing rate limiting in `rest-java`:**

The `web3` module has a full `ThrottleConfiguration` / `ThrottleManagerImpl` with bucket4j rate limiting. [4](#0-3) 

The `rest-java` module has **no equivalent**. Its only servlet filter is `MetricsFilter`, which only records byte counts and applies no admission control. [5](#0-4) 

The HikariCP datasource is created from `spring.datasource.hikari` properties with no explicit `maximumPoolSize` override found in `rest-java` resources (no `application.yml` exists under `rest-java/src/main/resources/`), meaning the default pool size of **10 connections** applies unless overridden at deployment time. [6](#0-5) 

**Exploit flow:**

1. Attacker picks any valid (or even invalid numeric) account ID — for `EntityIdNumParameter`, `entityService.lookup()` returns immediately without a DB query. [7](#0-6) 
2. Attacker sends N concurrent `GET /api/v1/accounts/1/airdrops/outstanding?limit=100` requests (N ≥ pool size).
3. Each request acquires one HikariCP connection and holds it while the DB query executes.
4. Once all pool connections are in use, every subsequent request (attacker's or legitimate user's) blocks waiting for a free connection.
5. After `connectionTimeout` (HikariCP default: 30 seconds), blocked threads throw `SQLTransientConnectionException`, returning HTTP 500 to all users.
6. Attacker sustains the flood to keep the pool permanently saturated.

**Why existing checks are insufficient:**

- `@Max(MAX_LIMIT)` on the `limit` parameter bounds result set size but does **not** limit request concurrency or connection acquisition rate. [8](#0-7) 
- No authentication is required on this endpoint.
- No IP-based or global request-rate filter exists in the `rest-java` filter chain.

### Impact Explanation

Complete denial of service for all `rest-java` API users. Once the HikariCP pool is exhausted, every endpoint that requires a DB connection (not just the airdrop endpoint) begins failing. The Prometheus alert `RestJavaHighDBConnections` (fires at 75% utilization) confirms the team recognizes connection pool pressure as a critical concern, but alerting does not prevent exploitation. [9](#0-8) 

### Likelihood Explanation

Preconditions: none — no account, no API key, no authentication. The attacker needs only a valid numeric account ID (any integer works for the lookup path) and a tool capable of high-concurrency HTTP requests (`wrk`, `hey`, `ab`). The attack is trivially repeatable and sustainable indefinitely. The asymmetry between `web3` (has rate limiting) and `rest-java` (has none) suggests this was an oversight rather than an intentional design choice.

### Recommendation

1. **Add a global rate-limiting filter to `rest-java`** mirroring the `ThrottleConfiguration` pattern already used in `web3`. Apply a per-IP token-bucket limit (e.g., 50–100 req/s per IP) and a global cap.
2. **Set an explicit `spring.datasource.hikari.maximum-pool-size`** in `rest-java` configuration and tune `connectionTimeout` to fail fast (e.g., 5 seconds) rather than queue for 30 seconds, limiting blast radius.
3. **Configure Tomcat's `server.tomcat.max-threads`** and `accept-count` to prevent unbounded thread accumulation while waiting for pool connections.
4. **Deploy an API gateway or WAF** in front of `rest-java` with per-IP rate limiting as a defense-in-depth layer.

### Proof of Concept

```bash
# Exhaust the default HikariCP pool (10 connections) with 20 concurrent workers
wrk -t20 -c200 -d60s \
  "http://<mirror-node-host>/api/v1/accounts/1/airdrops/outstanding?limit=100"

# In a separate terminal, observe legitimate requests failing:
curl -v "http://<mirror-node-host>/api/v1/accounts/2/airdrops/outstanding"
# Expected: HTTP 500 with SQLTransientConnectionException after ~30s
# (or immediate failure if connectionTimeout is already exceeded)
```

During the flood, the Grafana `hikaricp_connections_active` metric will show saturation at `hikaricp_connections_max`, and `hikaricp_connections_pending` will climb continuously, confirming pool exhaustion.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TokenAirdropsController.java (L66-75)
```java
    @GetMapping(value = "/outstanding")
    TokenAirdropsResponse getOutstandingAirdrops(
            @PathVariable EntityIdParameter id,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(name = RECEIVER_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] receiverIds,
            @RequestParam(name = SERIAL_NUMBER, required = false) @Size(max = 2) NumberRangeParameter[] serialNumbers,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        return processRequest(id, receiverIds, limit, order, serialNumbers, tokenIds, OUTSTANDING);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustomImpl.java (L58-72)
```java
    public Collection<TokenAirdrop> findAll(TokenAirdropRequest request, EntityId accountId) {
        var type = request.getType();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, type.getBaseField())
                .and(getBoundConditions(bounds))
                .and(TOKEN_AIRDROP.STATE.eq(AirdropState.PENDING));

        var order = SORT_ORDERS.getOrDefault(type, Map.of()).get(request.getOrder());
        return dslContext
                .selectFrom(TOKEN_AIRDROP)
                .where(condition)
                .orderBy(order)
                .limit(request.getLimit())
                .fetchInto(TokenAirdrop.class);
    }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L27-58)
```java
class MetricsFilter extends OncePerRequestFilter {

    static final String REQUEST_BYTES = "hiero.mirror.restjava.request.bytes";
    static final String RESPONSE_BYTES = "hiero.mirror.restjava.response.bytes";

    private static final String METHOD = "method";
    private static final String URI = "uri";

    private final MeterProvider<DistributionSummary> requestBytesProvider;
    private final MeterProvider<DistributionSummary> responseBytesProvider;

    MetricsFilter(MeterRegistry meterRegistry) {
        this.requestBytesProvider = DistributionSummary.builder(REQUEST_BYTES)
                .baseUnit("bytes")
                .description("The size of the request in bytes")
                .withRegistry(meterRegistry);
        this.responseBytesProvider = DistributionSummary.builder(RESPONSE_BYTES)
                .baseUnit("bytes")
                .description("The size of the response in bytes")
                .withRegistry(meterRegistry);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        try {
            filterChain.doFilter(request, response);
        } finally {
            recordMetrics(request, response);
        }
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L203-213)
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
