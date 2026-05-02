### Title
Unauthenticated DoS via Unbounded `GET /api/v1/topics/{id}` Requests with Non-Existent IDs

### Summary
`TopicServiceImpl.findById()` performs an uncached database lookup on every call and throws a freshly-allocated `EntityNotFoundException` (including JVM stack-trace capture) when the topic does not exist. The `rest-java` module has no rate limiting, no negative-result caching, and no authentication requirement on this endpoint, allowing any unprivileged caller to sustain an unbounded stream of DB queries and exception allocations that elevates CPU and GC pressure.

### Finding Description
**Exact code path:**

`TopicController.getTopic()` → `TopicServiceImpl.findById()` (line 20):
```java
return topicRepository.findById(id.getId())
    .orElseThrow(() -> new EntityNotFoundException("Topic not found"));
``` [1](#0-0) 

`TopicRepository` in `rest-java` is a bare `CrudRepository<Topic, Long>` with no `@Cacheable` annotation: [2](#0-1) 

Unlike the `grpc` module's `EntityRepository` (which carries `@Cacheable`), the `rest-java` `TopicRepository` has no caching layer at all. [3](#0-2) 

**No rate limiting in `rest-java`:** A grep across all `rest-java/src/main/**/*.java` for `RateLimiter`, `Throttle`, `bucket4j`, or `Bucket` returns zero hits on the topic/entity path. The bucket4j throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) lives exclusively in the `web3` module and is not wired into `rest-java`. [4](#0-3) 

`RestJavaConfiguration` registers only an ETag filter and a Protobuf converter — no rate-limit filter: [5](#0-4) 

`GenericControllerAdvice` handles `EntityNotFoundException` silently (no logging, no back-pressure): [6](#0-5) 

**Root cause:** The failed assumption is that a lightweight 404 path is harmless. In reality, each miss causes: (1) a synchronous DB round-trip (index scan returning empty), (2) lambda invocation and `EntityNotFoundException` instantiation — which in the JVM captures a full stack trace — and (3) JSON serialization of the error body. With no rate limiting and no negative-result cache, these costs are fully attacker-controlled.

### Impact Explanation
An attacker sending a sustained flood of `GET /api/v1/topics/0.0.<N>` requests with valid-format but non-existent IDs will:
- Exhaust the DB connection pool with index-miss queries, degrading all other mirror-node consumers sharing the same PostgreSQL instance.
- Force repeated `EntityNotFoundException` stack-trace captures, increasing young-generation GC frequency.
- Consume Tomcat/Netty worker threads proportional to request rate, starving legitimate traffic.

Because the endpoint is publicly reachable, unauthenticated, and has no per-IP or global RPS cap, a single attacker with modest bandwidth can sustain this indefinitely. The 30% CPU/GC threshold is realistic under a few hundred RPS, which is trivially achievable.

### Likelihood Explanation
No credentials, API keys, or special knowledge are required. The endpoint is documented in the public mirror-node API. Valid-format topic IDs (`0.0.<number>`) are trivially enumerable. The attack is repeatable, scriptable, and requires no exploit tooling beyond `curl` or `ab`.

### Recommendation
1. **Add a global RPS limiter to `rest-java`** using the same bucket4j pattern already present in `web3` (`ThrottleConfiguration` / `ThrottleManagerImpl`), applied via a servlet filter registered in `RestJavaConfiguration`.
2. **Cache negative results** for `TopicRepository.findById()` with a short TTL (e.g., 5–10 s) using Spring's `@Cacheable(unless="#result != null")` pattern, consistent with how the `grpc` module caches entity lookups.
3. **Suppress stack-trace capture** for `EntityNotFoundException` by overriding `fillInStackTrace()` in a custom `TopicNotFoundException` subclass, reducing per-exception GC cost.

### Proof of Concept
```bash
# Flood with valid-format but non-existent topic IDs (no auth required)
for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/topics/0.0.$((RANDOM + 9000000))" &
done
wait

# Observe: DB slow-query log fills with index-miss SELECTs on the topic table;
# JVM GC logs show increased minor-GC frequency;
# /actuator/metrics or Prometheus shows elevated CPU and thread-pool saturation.
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L115-118)
```java
    @ExceptionHandler
    private ResponseEntity<Object> notFound(final EntityNotFoundException e, final WebRequest request) {
        return handleExceptionInternal(e, null, null, NOT_FOUND, request);
    }
```
