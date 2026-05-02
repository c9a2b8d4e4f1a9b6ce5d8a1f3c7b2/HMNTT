### Title
Unauthenticated JDBC Connection Pool Exhaustion via Unbounded Concurrent Topic Lookups (DoS)

### Summary
The `rest-java` service exposes `/api/v1/topics/{id}` with no rate limiting, no authentication, and no caching for misses. Every request — including for non-existent IDs — acquires a HikariCP connection to execute a database query. Because the rest-java module has no documented or configured pool size cap and no request throttling (unlike the `web3` module which uses bucket4j), a flood of concurrent requests from an unprivileged attacker can exhaust the finite HikariCP connection pool, causing all subsequent legitimate requests to block waiting for a connection until they time out.

### Finding Description

**Exact code path:**

`TopicController.getTopic()` at [1](#0-0)  calls `topicService.findById(id.id())`.

`TopicServiceImpl.findById()` at [2](#0-1)  delegates directly to `topicRepository.findById(id.getId())` — a Spring Data `CrudRepository` method that unconditionally acquires a HikariCP connection and issues a `SELECT` against PostgreSQL.

`TopicRepository` is a bare `CrudRepository` extension with no custom logic, caching, or guard: [3](#0-2) 

**Root cause — no rate limiting in rest-java:**

The `web3` module has a full bucket4j throttle stack (`ThrottleConfiguration`, `ThrottleManagerImpl`) enforcing per-second request and gas limits. [4](#0-3) 

The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, `WebMvcConfiguration`, and `RestJavaConfiguration` — **none implement rate limiting or concurrency control.** [5](#0-4) 

**HikariCP pool — no rest-java-specific size configured:**

The shared `CommonConfiguration` wires HikariCP from `spring.datasource.hikari` properties. [6](#0-5) 

The rest-java documentation lists `hiero.mirror.restJava.db.statementTimeout` (10 000 ms) but **no `maximumPoolSize` property**, meaning the pool falls back to HikariCP's default of 10 connections. [7](#0-6) 

**Exploit flow:**

1. Attacker sends a sustained flood of `GET /api/v1/topics/0.0.999999999` (non-existent ID) requests with high concurrency.
2. Each request acquires a HikariCP connection, executes `SELECT … WHERE id = ?` (fast index miss, ~1–5 ms), then releases it.
3. At sufficient concurrency (>10 simultaneous in-flight queries), all pool connections are occupied; new requests queue inside HikariCP.
4. HikariCP's default `connectionTimeout` is 30 seconds — queued requests hold HTTP threads for up to 30 s waiting for a free connection.
5. Tomcat's HTTP thread pool (default 200) fills with blocked threads; legitimate requests receive 503 or timeout.
6. The rest-java ↔ PostgreSQL path is effectively severed for legitimate callers for the duration of the attack.

### Impact Explanation

All topic lookups — including valid ones from legitimate users — are denied service. The HikariCP pool is shared across all endpoints in the rest-java service, so exhaustion of the pool affects every database-backed endpoint, not just `/api/v1/topics/{id}`. The `statementTimeout` of 10 000 ms means a slow-query variant (e.g., targeting a table scan path) could hold connections even longer, amplifying the effect. Severity: **High** (unauthenticated, full service DoS).

### Likelihood Explanation

No privileges, API keys, or special knowledge are required. The endpoint is publicly documented in the OpenAPI spec. A single attacker with a modest HTTP load tool (e.g., `wrk`, `hey`, `k6`) can sustain the necessary concurrency. The attack is repeatable and stateless (no session required). The absence of any upstream rate-limiting configuration in the default deployment makes this trivially exploitable in a default-configured instance.

### Recommendation

1. **Add rate limiting to rest-java**: Introduce a bucket4j (or Spring Cloud Gateway) filter analogous to `ThrottleManagerImpl` in the `web3` module, applied globally to all `rest-java` endpoints.
2. **Increase and explicitly configure the HikariCP pool size** for rest-java and document it under `hiero.mirror.restJava.db.*` alongside the existing `statementTimeout` property.
3. **Cache negative (404) results**: A short-lived in-memory or Redis cache for non-existent topic IDs would prevent repeated DB hits for the same non-existent ID.
4. **Deploy an API gateway or ingress rate limiter** (e.g., nginx `limit_req`, Envoy, or a Kubernetes ingress annotation) as a defense-in-depth layer in front of the rest-java service.

### Proof of Concept

```bash
# Requires: wrk (https://github.com/wg/wrk)
# Target: default rest-java port 8080, non-existent topic ID

wrk -t 20 -c 200 -d 60s \
  http://<rest-java-host>:8080/api/v1/topics/0.0.999999999

# Expected result during attack:
# - Legitimate requests to /api/v1/topics/<valid-id> begin timing out
# - HikariCP pending connections metric spikes (hikaricp_connections_pending)
# - HTTP 503 or connection-timeout errors returned to legitimate callers
# - Grafana dashboard "Connection Pool" panel shows active == max, pending > 0
```

Monitoring confirmation: the Grafana dashboard for rest-java already tracks `hikaricp_connections_pending` — a sustained non-zero value during the attack confirms pool exhaustion. [8](#0-7)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L31-37)
```java
    @GetMapping(value = "/{id}")
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java (L1-8)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.restjava.repository;

import org.hiero.mirror.common.domain.topic.Topic;
import org.springframework.data.repository.CrudRepository;

public interface TopicRepository extends CrudRepository<Topic, Long> {}
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

**File:** docs/configuration.md (L622-634)
```markdown
| Name                                                     | Default                                            | Description                                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.restJava.db.host`                          | 127.0.0.1                                          | The IP or hostname used to connect to the database                                                                                                            |
| `hiero.mirror.restJava.db.name`                          | mirror_node                                        | The name of the database                                                                                                                                      |
| `hiero.mirror.restJava.db.password`                      | mirror_rest_java_pass                              | The database password used to connect to the database                                                                                                         |
| `hiero.mirror.restJava.db.port`                          | 5432                                               | The port used to connect to the database                                                                                                                      |
| `hiero.mirror.restJava.db.sslMode`                       | DISABLE                                            | The SSL level. Accepts either DISABLE, ALLOW, PREFER, REQUIRE, VERIFY_CA or VERIFY_FULL.                                                                      |
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
| `hiero.mirror.restJava.db.username`                      | mirror_rest_java                                   | The username used to connect to the database                                                                                                                  |
| `hiero.mirror.restJava.fee.refreshInterval`              | 10m                                                | How often to check for fee schedule updates from the database. Can accept duration units like `10s`, `2m` etc.                                                |
| `hiero.mirror.restJava.network.unreleasedSupplyAccounts` | 2-2, 42-42, 44-71, 73-87, 99-100, 200-349, 400-750 | Account ranges holding unreleased HBAR supply, excluded from circulating supply calculations                                                                  |
| `hiero.mirror.restJava.response.headers.defaults`        | See application.yml                                | The default headers to add to every response. For each header, specify its `name: value`                                                                      |
| `hiero.mirror.restJava.response.headers.path`            | See application.yml                                | Override default or add headers per path to add to every response. The key is the controller request mapping, then for each header, specify its `name: value` |
```

**File:** charts/hedera-mirror-common/dashboards/hedera-mirror-rest-java.json (L1630-1641)
```json
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
