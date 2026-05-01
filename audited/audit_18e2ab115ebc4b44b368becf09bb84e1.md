### Title
HTTP/2 Multiplexing Exhausts HikariCP Connection Pool via Unauthenticated `GET /api/v1/topics/{id}`

### Summary
The `rest-java` module exposes `GET /api/v1/topics/{id}` with no rate limiting. Each request triggers three sequential database queries through `TopicRepository.findById()`, `EntityService.findById()`, and `CustomFeeService.findById()`. An unauthenticated attacker can open a single HTTP/2 connection and flood it with hundreds of concurrent streams, exhausting the HikariCP connection pool and rendering the mirror node instance unresponsive.

### Finding Description

**Exact code path:**

`TopicController.getTopic()` (line 32–37) makes three sequential, uncached service calls per request:

```java
var topic = topicService.findById(id.id());       // → TopicRepository.findById()
var entity = entityService.findById(id.id());     // → EntityRepository
var customFee = customFeeService.findById(id.id()); // → CustomFeeRepository
``` [1](#0-0) 

`TopicServiceImpl.findById()` delegates directly to `topicRepository.findById()` with no caching layer: [2](#0-1) 

`TopicRepository` is a bare `CrudRepository` with no custom query logic: [3](#0-2) 

**Root cause — no rate limiting in rest-java:**

`RestJavaConfiguration` registers only a `ShallowEtagHeaderFilter` and a `ProtobufHttpMessageConverter`. No rate-limiting filter is registered: [4](#0-3) 

`WebMvcConfiguration` adds only argument resolvers and formatters: [5](#0-4) 

`LoggingFilter` only logs requests: [6](#0-5) 

A grep across all `rest-java/src/main/**/*.java` for `RateLimiter`, `throttle`, `bucket4j`, or `RequestRateLimiter` returns zero matches on the topics path. The `ThrottleConfiguration` and `ThrottleManagerImpl` with bucket4j exist exclusively in the `web3` module (for EVM contract calls): [7](#0-6) 

**HikariCP pool as the bottleneck:**

The `DataSource` bean is a `HikariDataSource` configured via `spring.datasource.hikari` properties. No explicit `maximumPoolSize` override was found in `rest-java` resources, meaning the Spring Boot default of **10 connections** applies. The Grafana dashboard and Prometheus alert confirm this pool is monitored but not protected: [8](#0-7) [9](#0-8) 

### Impact Explanation

With HTTP/2 multiplexing, a single TCP connection can carry hundreds of concurrent streams. Each stream maps to a Spring MVC thread that holds a HikariCP connection for the duration of three sequential DB queries. With a pool of 10 connections and hundreds of concurrent streams, the pool is exhausted immediately. All subsequent requests block at `HikariPool.getConnection()` until the `connectionTimeout` (default 30 s) expires, returning 500 errors to all clients. This degrades or completely halts the mirror node instance's REST API, satisfying the ≥30% network processing degradation threshold. If the underlying PostgreSQL server is shared across instances, the attack amplifies across all nodes.

### Likelihood Explanation

The attack requires no credentials, no special tooling beyond a standard HTTP/2 client (e.g., `h2load`, `curl --http2`, Python `httpx`), and no prior knowledge of the system beyond the public API path. The endpoint is documented in the OpenAPI spec. The attack is trivially repeatable and can be sustained indefinitely from a single machine. No existing application-layer control (WAF, API gateway rate limiting) is visible in the codebase itself.

### Recommendation

1. **Add rate limiting to rest-java**: Introduce a bucket4j or Resilience4j `RateLimiter` filter in `RestJavaConfiguration` scoped to `/api/v1/**`, mirroring the pattern already used in `web3/ThrottleConfiguration`.
2. **Set an explicit HikariCP pool size** in `rest-java`'s application configuration and tune `connectionTimeout` downward to fail fast rather than queue.
3. **Enforce HTTP/2 stream concurrency limits** at the ingress/load-balancer layer (`SETTINGS_MAX_CONCURRENT_STREAMS`).
4. **Add per-IP connection/request rate limiting** at the infrastructure layer (e.g., Nginx `limit_req`, Envoy local rate limit).
5. **Add a caching layer** (e.g., Spring Cache with Caffeine) on `TopicServiceImpl.findById()` to reduce DB pressure for repeated lookups of the same topic ID.

### Proof of Concept

```bash
# Install h2load (part of nghttp2)
# Send 500 concurrent HTTP/2 requests over 1 connection to a single mirror node instance
h2load -n 500 -c 1 -m 500 \
  https://<mirror-node-host>/api/v1/topics/0.0.1234

# Expected result:
# - HikariCP pool (10 connections) exhausted within milliseconds
# - Requests queue and begin timing out after connectionTimeout (default 30s)
# - Mirror node REST API returns HTTP 500 for all subsequent requests
# - hikaricp_connections_pending metric spikes; hikaricp_connections_active stays at max
```

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-31)
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
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/LoggingFilter.java (L27-38)
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
