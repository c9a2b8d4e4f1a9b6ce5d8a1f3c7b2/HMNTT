### Title
Uncached, Unthrottled `TopicServiceImpl.findById()` Enables DB Connection Pool Exhaustion via Concurrent Request Flood

### Summary
`TopicServiceImpl.findById()` delegates directly to `TopicRepository.findById()` with no caching, no rate limiting, and no request coalescing. Unlike other repositories in the codebase that use `@Cacheable`, `TopicRepository` is a bare `CrudRepository` with no cache annotation. The rest-java module has no rate-limiting layer (unlike the web3 module which has `ThrottleConfiguration`). An unprivileged attacker can flood `GET /api/v1/topics/{id}` with thousands of concurrent requests for the same topic ID, exhausting the HikariCP connection pool and degrading mirror node REST API throughput.

### Finding Description
**Exact code path:**

`TopicServiceImpl.findById()` at [1](#0-0)  calls `topicRepository.findById(id.getId())` unconditionally on every invocation.

`TopicRepository` is declared as: [2](#0-1)  — a plain `CrudRepository` with no `@Cacheable` annotation.

Compare this to the grpc module's `EntityRepository`, which applies `@Cacheable` with a 24-hour TTL: [3](#0-2)  — the same pattern is absent from rest-java's `TopicRepository`.

**Per-request DB amplification:** `TopicController.getTopic()` makes 3 sequential DB calls per request — `topicService.findById()`, `entityService.findById()`, and `customFeeService.findById()`: [4](#0-3) 

**No rate limiting in rest-java:** The only throttle/rate-limit infrastructure in the codebase lives in the `web3` module: [5](#0-4)  — no equivalent exists in rest-java.

**Root cause:** The failed assumption is that the DB or an upstream proxy will absorb concurrent identical reads. There is no in-process cache, no request coalescing (e.g., Caffeine's `refreshAfterWrite` or a `LoadingCache`), and no per-IP or global rate limiter in the rest-java request path.

### Impact Explanation
Each concurrent request for the same topic ID issues a fresh `SELECT` against the `topic` table (plus `entity` and `custom_fee`). With thousands of concurrent requests, the HikariCP connection pool — monitored via `hikaricp_connections_active` and alerting at 75% utilization — becomes saturated: [6](#0-5)  All subsequent REST API requests queue or fail with connection timeout errors, degrading mirror node REST throughput by the fraction of the pool consumed. Because the rest-java DB pool is shared across all endpoints, flooding `/api/v1/topics/{id}` starves other endpoints (token airdrops, allowances, network nodes) of DB connections, constituting a cross-endpoint DoS.

### Likelihood Explanation
No authentication is required — `GET /api/v1/topics/{id}` is a public, unauthenticated endpoint. The attacker needs only a valid topic ID (trivially discoverable from any block explorer or by iterating small integers). The attack is repeatable, scriptable with standard HTTP load tools (e.g., `wrk`, `ab`, `hey`), and requires no special privileges or knowledge beyond the public API surface. The absence of any IP-based throttle or circuit breaker in rest-java makes this continuously exploitable.

### Recommendation
1. Add `@Cacheable` to `TopicRepository.findById()` using a short-TTL Caffeine cache (e.g., 5–30 seconds), consistent with the pattern used in `grpc/EntityRepository`.
2. Introduce a global rate-limiting filter in rest-java (mirroring `web3/ThrottleConfiguration`) using Bucket4j or Spring's `HandlerInterceptor`.
3. Consider request coalescing via Caffeine's `AsyncLoadingCache` to collapse concurrent identical key lookups into a single DB round-trip.
4. Ensure the rest-java DB pool is isolated from the importer's write pool to limit blast radius.

### Proof of Concept
```bash
# Precondition: topic ID 1000 exists (verify with a single GET first)
curl -s http://<mirror-node>/api/v1/topics/1000

# Flood with 5000 concurrent requests for the same topic ID
hey -n 5000 -c 500 http://<mirror-node>/api/v1/topics/1000

# Observable result:
# - hikaricp_connections_active approaches hikaricp_connections_max
# - Other /api/v1/* endpoints begin returning 500 or timing out
# - spring_data_repository_invocations_seconds_sum spikes (alert threshold: >1s avg)
# - No 429 responses are returned at any point (no rate limiter present)
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TopicRepository.java (L1-9)
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L32-37)
```java
    Topic getTopic(@PathVariable EntityIdNumParameter id) {
        var topic = topicService.findById(id.id());
        var entity = entityService.findById(id.id());
        var customFee = customFeeService.findById(id.id());
        return topicMapper.map(customFee, entity, topic);
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
