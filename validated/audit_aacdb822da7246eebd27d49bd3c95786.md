All code references in the claim have been verified against the actual codebase. Here is the audit result:

---

# Audit Report

## Title
Unauthenticated Flood of `GET /api/v1/network/stake` Triggers False Positive `DOWN` Health Status in Monitor

## Summary
The `GET /api/v1/network/stake` endpoint in the `rest-java` module has no rate limiting and its backing `NetworkStakeRepository.findLatest()` executes an uncached correlated subquery on every request. The monitor's `SubscriberHealthIndicator` uses the HTTP status code of this endpoint as a hard gate: any 5xx response unconditionally sets the entire mirror node health to `DOWN`, regardless of actual publish/subscribe activity. An unprivileged attacker can flood this endpoint to exhaust the DB connection pool, induce 500 errors, and cause the monitoring system to report the mirror node as DOWN.

## Finding Description

**Step 1 — Unauthenticated, unthrottled endpoint:**

`NetworkController.getNetworkStake()` has no authentication, no rate limiting, and no parameters: [1](#0-0) 

**Step 2 — No caching in the service layer:**

`NetworkServiceImpl.getLatestNetworkStake()` calls the repository directly with no `@Cacheable` or result reuse: [2](#0-1) 

**Step 3 — Correlated subquery on every call:**

`NetworkStakeRepository.findLatest()` executes a correlated subquery (`SELECT MAX(consensus_timestamp) FROM network_stake`) on every invocation with no caching annotation: [3](#0-2) 

**Step 4 — Monitor polls this endpoint for raw status code:**

`RestApiClient.getNetworkStakeStatusCode()` polls `/network/stake` and returns the raw HTTP status code: [4](#0-3) 

**Step 5 — 5xx maps unconditionally to `Status.DOWN`:**

`SubscriberHealthIndicator.restNetworkStakeHealth()` maps any 5xx response to `Status.DOWN`: [5](#0-4) 

**Step 6 — `health()` uses `restNetworkStakeHealth()` as a hard gate:**

If `restNetworkStakeHealth()` does not return `Status.UP`, the entire health check short-circuits and returns that status without evaluating publish/subscribe rates: [6](#0-5) 

**Step 7 — Rate limiting is absent from `rest-java`:**

The only throttle configuration in the codebase is in the `web3` module and applies exclusively to contract call requests: [7](#0-6) 

A grep across all `rest-java/src/**/*.java` for `RateLimiter`, `rate.limit`, `throttle`, or `@RateLimit` returns only references to the `HIGH_VOLUME_THROTTLE` fee-estimation parameter — not HTTP-level rate limiting. No equivalent `ThrottleConfiguration` exists in `rest-java`.

## Impact Explanation

The test matrix in `SubscriberHealthIndicatorTest` confirms that even with a healthy publish rate (1.0) and subscribe rate (1.0), a 500 from the stake endpoint produces `DOWN`: [8](#0-7) 

When `health()` returns `DOWN`, the `CLUSTER_UP` gauge metric is set to 0: [9](#0-8) 

This causes the monitoring system to report the mirror node as completely unavailable and triggers incident response workflows for a condition that does not reflect actual node health. The `rest-java` service's DB pool exhaustion does not affect the importer, grpc, or other subsystems, making this a genuine false positive at the mirror-node level.

## Likelihood Explanation

The endpoint requires no authentication, no API key, and accepts no parameters. Any attacker with network access to the mirror node's REST Java API can execute this attack with a standard HTTP flood tool (`ab`, `wrk`, `hey`). The correlated subquery `SELECT MAX(consensus_timestamp) FROM network_stake` is executed on every request with no caching, making concurrent DB connection saturation achievable at sustained request rates. The attack is repeatable and requires no special knowledge beyond the public API documentation. [10](#0-9) 

## Recommendation

1. **Add response caching** to `NetworkStakeRepository.findLatest()` (e.g., Spring `@Cacheable` with a short TTL such as 30–60 seconds), mirroring the pattern already used in `grpc`'s `NodeStakeRepository.findAllStakeByConsensusTimestamp()`. [11](#0-10) 

2. **Add HTTP-level rate limiting** to the `rest-java` module for network endpoints, analogous to the `ThrottleConfiguration` already present in `web3`.

3. **Decouple the health gate** in `SubscriberHealthIndicator.health()`: a 5xx from the stake endpoint should contribute to health status but not unconditionally override healthy publish/subscribe rates. Consider returning `UNKNOWN` instead of `DOWN` for stake endpoint failures when pub/sub rates are healthy.

## Proof of Concept

```bash
# Flood the unauthenticated endpoint to exhaust the DB connection pool
wrk -t 10 -c 200 -d 60s http://<mirror-node-rest-java>/api/v1/network/stake

# Monitor health endpoint will report DOWN
curl http://<monitor>/actuator/health
# {"status":"DOWN","components":{"subscriber":{"status":"DOWN","details":{"reason":"Network stake status is DOWN with status code 500"}}}}
```

The `CLUSTER_UP` gauge metric will drop to 0, triggering any configured alerting rules.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L51-56)
```java
    @Override
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

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestApiClient.java (L67-69)
```java
    public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
        return webClientRestJava.get().uri("/network/stake").exchangeToMono(r -> Mono.just(r.statusCode()));
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L59-63)
```java
    public Mono<Health> health() {
        return restNetworkStakeHealth()
                .flatMap(health ->
                        health.getStatus() == Status.UP ? publishing().switchIfEmpty(subscribing()) : Mono.just(health))
                .doOnNext(this::recordHealthMetric);
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L66-69)
```java
    private void recordHealthMetric(Health health) {
        final var status = health != null ? health.getStatus() : Status.UP;
        CLUSTER_UP.set(Status.UP.equals(status) ? 1 : 0);
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L93-106)
```java
    private Mono<Health> restNetworkStakeHealth() {
        return restApiClient
                .getNetworkStakeStatusCode()
                .flatMap(statusCode -> {
                    if (statusCode.is2xxSuccessful()) {
                        return UP;
                    }

                    var status = statusCode.is5xxServerError() ? Status.DOWN : Status.UNKNOWN;
                    var statusMessage =
                            String.format("Network stake status is %s with status code %s", status, statusCode.value());
                    log.error(statusMessage);
                    return health(status, statusMessage);
                })
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L1-55)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.web3.config;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.local.SynchronizationStrategy;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.hiero.mirror.web3.throttle.ThrottleProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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

**File:** monitor/src/test/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicatorTest.java (L63-82)
```java
    @CsvSource({
        "1.0, 1.0, 200, UP, false", // healthy
        "0.0, 1.0, 200, UNKNOWN, false", // publishing inactive
        "1.0, 0.0, 200, UNKNOWN, false", // subscribing inactive
        "0.0, 0.0, 200, UNKNOWN, false", // publishing and subscribing inactive
        "1.0, 1.0, 400, UNKNOWN, false", // unknown network stake
        "1.0, 1.0, 500, DOWN, false", // network stake down
        "0.0, 0.0, 500, DOWN, false", // publishing and subscribing inactive and network stake down
        "0.0, 1.0, 500, DOWN, false", // network stake down and publishing inactive
        "1.0, 0.0, 500, DOWN, false", // network stake down and subscribing inactive
        "1.0, 1.0, 200, UP, true", // healthy
        "0.0, 1.0, 500, DOWN, true", // publishing inactive
        "1.0, 0.0, 500, DOWN, true", // subscribing inactive
        "0.0, 0.0, 500, DOWN, true", // publishing and subscribing inactive
        "1.0, 1.0, 400, UNKNOWN, true", // unknown network stake
        "1.0, 1.0, 500, DOWN, true", // network stake down
        "0.0, 0.0, 500, DOWN, true", // publishing and subscribing inactive and network stake down
        "0.0, 1.0, 500, DOWN, true", // network stake down and publishing inactive
        "1.0, 0.0, 500, DOWN, true", // network stake down and subscribing inactive
    })
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L23-28)
```java
    // An empty map may be cached, indicating the node_stake table is empty
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```
