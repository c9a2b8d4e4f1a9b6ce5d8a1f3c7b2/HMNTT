### Title
Unauthenticated Rate-Unlimited `account()` GraphQL Query Enables Connection Pool Exhaustion DoS

### Summary
The `account()` query endpoint in `AccountController` is publicly accessible with no rate limiting, no authentication, and no concurrency control. An unprivileged attacker can flood the endpoint with concurrent valid requests, exhausting the HikariCP database connection pool (default 10 connections), causing all subsequent legitimate requests to queue and time out, effectively partitioning the application from the database.

### Finding Description

**Exact code path:**

`AccountController.account()` at [1](#0-0)  accepts any unauthenticated POST to `/graphql/alpha` and immediately calls `entityService.getByIdAndType()` → `entityRepository.findById()`, which acquires a HikariCP connection from the shared pool.

**Root cause — no rate limiting in the graphql module:**

A grep across all `graphql/**/*.java` files for `rateLimiter`, `RateLimiter`, `throttle`, `bucket4j`, or `resilience4j` returns **zero results**. The only filters registered are in `GraphQlConfiguration`:
- `MaxQueryComplexityInstrumentation(200)` — limits query structure complexity [2](#0-1) 
- `MaxQueryDepthInstrumentation(10)` — limits nesting depth [3](#0-2) 
- JSON/parser size limits — reject oversized payloads [4](#0-3) 

None of these limit **request rate or concurrency per client**.

**Failed assumption — asymmetric protection:**

The `web3` module explicitly implements token-bucket rate limiting via `ThrottleConfiguration` (bucket4j) with `requestsPerSecond = 500` and gas-per-second limits. [5](#0-4)  The `graphql` module has no equivalent. This is a deliberate design gap, not an oversight in the web3 module.

**Connection pool — finite shared resource:**

`CommonConfiguration` creates a `HikariDataSource` bound to `spring.datasource.hikari` properties. [6](#0-5)  The graphql module has **no explicit `maximumPoolSize` override** (confirmed by grep returning zero results for `hikari`/`maximumPoolSize` in `graphql/**`), so HikariCP's default of **10 connections** applies. HikariCP's default `connectionTimeout` is 30 seconds — meaning queued requests block for up to 30 seconds before failing.

**No authentication:**

No `SecurityFilterChain`, `HttpSecurity`, or Spring Security configuration exists anywhere in `graphql/src/main/java/`. The `LoggingFilter` only logs requests; it enforces nothing. [7](#0-6) 

### Impact Explanation

With 10 HikariCP connections and no rate limiting, an attacker sending ≥10 concurrent requests holds all connections. Every subsequent legitimate request queues for up to 30 seconds (HikariCP `connectionTimeout`) then fails with `Connection is not available, request timed out`. This is a complete application-layer partition from the database — all GraphQL queries fail for all users until the attacker stops. The `GraphQLHighDBConnections` Prometheus alert fires only after 5 minutes at >75% utilization, [8](#0-7)  meaning the service is already fully degraded before any automated response triggers.

### Likelihood Explanation

**Preconditions:** None. The endpoint is unauthenticated and publicly documented at `http://<host>:8083/graphql/alpha`. [9](#0-8) 

**Attacker capability:** Any script kiddie with `curl` or `ab` (Apache Bench). No credentials, no tokens, no special knowledge required.

**Repeatability:** Fully repeatable and automatable. A single machine with a modest number of concurrent HTTP connections suffices.

### Recommendation

1. **Add a token-bucket rate limiter** to the graphql module mirroring the web3 `ThrottleConfiguration` — apply it as a `WebGraphQlInterceptor` or a servlet filter before the GraphQL execution pipeline.
2. **Set an explicit `spring.datasource.hikari.maximumPoolSize`** in the graphql application properties and configure `connectionTimeout` to a low value (e.g., 2–5 seconds) so queued requests fail fast rather than holding threads.
3. **Add per-IP concurrency limiting** at the load balancer or ingress layer (as already noted in `docs/design/contract-log-subscription.md`: "We should implement rate limiting in the load balancer"). [10](#0-9) 
4. **Require authentication** or at minimum enforce a `max_user_client_connections` limit at the pgbouncer layer for the `mirror_graphql` user, analogous to what is done for `mirror_rest` and `mirror_web3`. [11](#0-10) 

### Proof of Concept

```bash
# Send 50 concurrent valid account queries with no credentials
# Requires: curl, GNU parallel or xargs

for i in $(seq 1 50); do
  curl -s -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{account(input:{entityId:{shard:0,realm:0,num:2}}){balance}}"}' &
done
wait

# From a second terminal, observe legitimate requests timing out:
curl -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{account(input:{entityId:{shard:0,realm:0,num:2}}){balance}}"}'
# Expected result: HikariPool connection timeout error or HTTP 500 after 30s
```

The attack requires no authentication, no special payload, and is repeatable indefinitely. Varying `num` values across requests prevents any query-level caching from mitigating the pool exhaustion.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-58)
```java
    @QueryMapping
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
        }

        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        throw new IllegalStateException("Not implemented");
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L31-38)
```java
    static {
        // Configure GraphQL parsing limits to reject malicious input
        Consumer<Builder> consumer =
                b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
        ParserOptions.setDefaultParserOptions(
                ParserOptions.getDefaultParserOptions().transform(consumer));
        ParserOptions.setDefaultOperationParserOptions(
                ParserOptions.getDefaultOperationParserOptions().transform(consumer));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/LoggingFilter.java (L27-38)
```java
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

**File:** charts/hedera-mirror-graphql/values.yaml (L204-214)
```yaml
  GraphQLHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror GraphQL API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="graphql"}) by (namespace, pod) / sum(hikaricp_connections_max{application="graphql"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: graphql
      area: resource
      severity: critical
```

**File:** docs/graphql/README.md (L34-36)
```markdown
curl -X POST http://localhost:8083/graphql/alpha -H 'Content-Type: application/json' \
  -d '{"query": "{account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance }}"}'
```
```

**File:** docs/design/contract-log-subscription.md (L37-37)
```markdown
- We should implement rate limiting in the load balancer
```

**File:** charts/hedera-mirror/values.yaml (L371-376)
```yaml
        mirror_rest:
          max_user_client_connections: 1000
          max_user_connections: 250
        mirror_web3:
          max_user_client_connections: 1000
          max_user_connections: 250
```
