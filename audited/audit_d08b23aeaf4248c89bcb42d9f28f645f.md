### Title
Unauthenticated Concurrent Request Flood Exhausts DB Connection Pool via Unthrottled `getAirdrops()` Endpoint

### Summary
The `GET /api/v1/accounts/{id}/airdrops/outstanding` endpoint in the `rest-java` module has no rate limiting, no authentication, and no concurrency control. Any unprivileged external user can flood this endpoint with concurrent requests, each of which acquires a database connection via `repository.findAll()`, exhausting the HikariCP connection pool and causing all subsequent requests — including transaction status queries — to fail or timeout until the attack stops.

### Finding Description

**Exact code path:**

`TokenAirdropsController.getOutstandingAirdrops()` (lines 66–75) accepts unauthenticated GET requests with `limit` validated only by `@Max(MAX_LIMIT)` where `MAX_LIMIT = 100`. It delegates to `processRequest()` which calls `service.getAirdrops(request)`. [1](#0-0) 

`TokenAirdropServiceImpl.getAirdrops()` (lines 19–22) makes **two** sequential database calls: `entityService.lookup()` (entity table lookup) and `repository.findAll()` (token_airdrop table query), each consuming a connection from the shared HikariCP pool for the duration of the call. [2](#0-1) 

`TokenAirdropRepositoryCustomImpl.findAll()` (lines 58–72) executes a JOOQ query with `LIMIT request.getLimit()` — bounded to 100 rows, but the query still holds a DB connection for its full execution duration. [3](#0-2) 

**Root cause — no rate limiting in `rest-java`:**

The `rest-java` module's only servlet filters are `LoggingFilter` and `MetricsFilter` — neither throttles requests. [4](#0-3) [5](#0-4) 

The `ThrottleConfiguration` (bucket4j-based rate limiter) exists only in the `web3` module, not in `rest-java`. [6](#0-5) 

`WebMvcConfiguration` in `rest-java` registers only argument resolvers and formatters — no rate-limiting interceptors. [7](#0-6) 

`RestJavaProperties` and `QueryProperties` contain no concurrency or rate-limit configuration. [8](#0-7) 

**Connection pool:**

HikariCP is configured via `spring.datasource.hikari`. The Node.js REST API documentation shows the default `maxConnections` is 10 for the mirror node stack. The `rest-java` module has no override in its resources directory (only `banner.txt` exists under `rest-java/src/main/resources/`). Spring Boot's HikariCP default is also 10 connections. [9](#0-8) 

**Exploit flow:**

1. Attacker sends N concurrent `GET /api/v1/accounts/0.0.1/airdrops/outstanding?limit=100` requests (no auth required).
2. Each request acquires a Tomcat worker thread and then blocks waiting for a HikariCP connection.
3. With 10 connections in the pool, 10 requests execute simultaneously; the remaining N−10 threads block in HikariCP's wait queue for up to `connectionTimeout` (default 30s).
4. With N ≥ Tomcat's max thread count (default 200), the Tomcat thread pool is fully saturated.
5. All new incoming requests — including transaction status queries on other endpoints — are queued at the OS socket accept queue and receive no response until threads free up.
6. The attacker maintains the flood continuously; as soon as one batch of connections times out, a new batch is sent.

**Why existing checks are insufficient:**

- `@Max(MAX_LIMIT)` (line 69) limits result set size to 100 rows but does not limit the number of concurrent requests or the connection hold time. [10](#0-9) 
- `@Size(max = 2)` on filter parameters limits query complexity slightly but does not prevent pool exhaustion.
- No IP-based throttling, no session-based limits, no API key requirement.

### Impact Explanation

An attacker with no credentials can render the mirror node REST Java service unresponsive to all requests. Since the mirror node is the primary interface for querying Hedera transaction status (e.g., `GET /api/v1/transactions/{id}`), this prevents clients and applications from confirming whether submitted transactions were accepted by the network. The impact is a full DoS of the mirror node REST API service. The Hedera consensus network itself is unaffected, but all mirror-node-dependent transaction confirmation workflows are blocked for the duration of the attack.

### Likelihood Explanation

This requires zero privileges, zero authentication, and only a standard HTTP client capable of sending concurrent requests (e.g., `ab`, `wrk`, `hey`, or a simple script). The attack is trivially repeatable and can be sustained indefinitely. Any public-facing deployment of the mirror node is exposed. The attacker does not need to know valid account IDs — any syntactically valid ID (e.g., `0.0.1`) will trigger the full DB query path (the query simply returns 0 rows for non-existent accounts, but still acquires and holds a connection).

### Recommendation

1. **Add rate limiting to `rest-java`**: Introduce a bucket4j-based `HandlerInterceptor` or servlet filter in `rest-java` (mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`) that limits requests per IP per second.
2. **Increase connection pool size** or configure a shorter `connectionTimeout` to fail fast under load rather than holding threads.
3. **Configure Tomcat's `maxConnections` and `acceptCount`** to bound the number of queued connections at the server level.
4. **Add a `statement_timeout`** at the DB level for the rest-java datasource to bound how long any single query can hold a connection.
5. **Deploy an API gateway or reverse proxy** (e.g., nginx, Envoy) with per-IP connection and request rate limits in front of the mirror node.

### Proof of Concept

```bash
# Flood the endpoint with 500 concurrent requests, 5000 total
# No authentication required
ab -n 5000 -c 500 \
  "http://<mirror-node-host>:8080/api/v1/accounts/0.0.1/airdrops/outstanding?limit=100"

# Simultaneously, observe that legitimate transaction queries time out:
curl -v "http://<mirror-node-host>:8080/api/v1/transactions/0.0.3-1234567890-000000000"
# Expected: connection hangs or returns 503/timeout

# The attack requires no credentials, no special headers, and works
# against any valid or invalid account ID.
```

**Verification steps:**
1. Start the mirror node `rest-java` service with default configuration.
2. Run the `ab` command above from any external host.
3. Observe HikariCP pool exhaustion in logs (`HikariPool-1 - Connection is not available, request timed out after 30000ms`).
4. Observe Tomcat thread pool saturation via actuator metrics (`/actuator/metrics/tomcat.threads.busy`).
5. Confirm that concurrent legitimate API calls to other endpoints receive no response or timeout errors.

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/LoggingFilter.java (L18-38)
```java
class LoggingFilter extends OncePerRequestFilter {

    @SuppressWarnings("java:S1075")
    private static final String ACTUATOR_PATH = "/actuator/";

    private static final String LOG_FORMAT = "{} {} {} in {} ms: {} {}";
    private static final String SUCCESS = "Success";

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-32)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-32)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
final class WebMvcConfiguration implements WebMvcConfigurer {

    private final RequestParameterArgumentResolver requestParameterArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(requestParameterArgumentResolver);
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class, EntityIdParameter.class, EntityIdParameter::valueOf);
    }
}
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/QueryProperties.java (L1-17)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.restjava.service;

import jakarta.validation.constraints.Min;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Data
@Validated
@ConfigurationProperties("hiero.mirror.rest-java.query")
public final class QueryProperties {

    @Min(1)
    private int maxFileAttempts = 12;
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
