### Title
DoS-Induced False Cluster-Down via Unauthenticated `/network/stake` Flooding Exhausting Monitor's 5-Second Timeout

### Summary
The `restNetworkStakeHealth()` method in `SubscriberHealthIndicator` issues a single unauthenticated outbound HTTP GET to `/network/stake` with a hard-coded 5-second timeout and no retry, no caching, and no grace period. Because the `rest-java` `/network/stake` endpoint has zero application-level rate limiting, an unprivileged attacker can flood it to saturate the service's thread pool and database connection pool, causing the monitor's probe to time out, which is unconditionally mapped to `Status.DOWN`, immediately driving the `CLUSTER_UP` gauge to 0 and triggering false automated remediation or alerting.

### Finding Description

**Exact code path:**

`SubscriberHealthIndicator.java` — `restNetworkStakeHealth()` (lines 93–121): [1](#0-0) 

The chain is:
1. `restApiClient.getNetworkStakeStatusCode()` issues a plain GET to `/network/stake` with no retry. [2](#0-1) 
2. `.timeout(Duration.ofSeconds(5))` fires a `TimeoutException` if no response arrives within 5 s. [3](#0-2) 
3. `onErrorResume` unconditionally maps `TimeoutException` (and `ConnectException`) to `Status.DOWN`. [4](#0-3) 
4. `recordHealthMetric` immediately sets the static `CLUSTER_UP` gauge to 0. [5](#0-4) 

**Root cause — failed assumption:** The design assumes the REST API will always respond within 5 seconds under any external load. There is no retry, no cached last-known-good state, and no distinction between a genuine outage and a load-induced slowdown.

**Why the endpoint is attackable:** `NetworkController.getNetworkStake()` is a public, unauthenticated `@GetMapping` with no application-level rate limiting in the `rest-java` service. [6](#0-5) 

Every request executes a correlated subquery against the database: [7](#0-6) 

The only throttling in the codebase is in the `web3` service for contract calls — it does not apply to `rest-java` network endpoints. [8](#0-7) 

The GCP backend policy sets `maxRatePerEndpoint: 250` (per pod, not per client/IP), which is a throughput cap, not a per-source rate limit, and does not prevent a distributed flood from saturating the DB connection pool. [9](#0-8) 

### Impact Explanation
A sustained flood causes the monitor to emit `Status.DOWN` on every health-check cycle. `CLUSTER_UP` (a Micrometer `Gauge` scraped by Prometheus) drops to 0, which is the canonical signal used by automated alerting and remediation pipelines to declare the cluster down. This can trigger unnecessary failovers, incident pages, or auto-scaling actions — a false cluster-down with no actual service degradation. The `SubscriberHealthIndicator` test `restNetworkStakeTimeoutException` explicitly confirms that a 6-second delay produces `Status.DOWN` with `CLUSTER_UP = 0`. [10](#0-9) 

### Likelihood Explanation
The `/network/stake` endpoint requires no authentication, accepts no parameters, and is publicly documented in the OpenAPI spec. [11](#0-10) 

A single attacker with modest bandwidth can issue thousands of concurrent GET requests. Each request hits the database with a correlated subquery, exhausting the connection pool and causing response latency to exceed 5 seconds. The attack is repeatable, requires no credentials, and can be sustained indefinitely. The project even ships a k6 load-test script targeting this exact endpoint, demonstrating that high-volume access is a known and tested scenario. [12](#0-11) 

### Recommendation
1. **Add retry with backoff** in `restNetworkStakeHealth()` before concluding `Status.DOWN` (e.g., `retryWhen(Retry.backoff(2, Duration.ofMillis(500)))`).
2. **Cache the last successful health result** for a short window (e.g., 10–15 s) so a single timeout does not immediately flip `CLUSTER_UP` to 0.
3. **Add application-level rate limiting** to the `rest-java` `/network/stake` endpoint (per-IP or global), analogous to the existing `ThrottleConfiguration` in the `web3` service.
4. **Require consecutive failures** (e.g., 2–3 consecutive timeouts) before setting `Status.DOWN`, eliminating single-probe false positives.

### Proof of Concept
```
# Step 1 – flood /network/stake from an unprivileged host
ab -n 100000 -c 500 https://<mirror-node-rest-java>/api/v1/network/stake &

# Step 2 – while the flood is running, poll the monitor health endpoint
watch -n 1 curl -s http://<monitor-host>:8080/actuator/health | jq '.components.subscriber'

# Expected observation:
# - "status": "DOWN" appears within one health-check cycle (default Spring Boot: every 10 s)
# - Prometheus metric hiero_mirror_monitor_health{type="cluster"} drops to 0
# - Any alert rule on CLUSTER_UP == 0 fires, triggering false remediation
```

### Citations

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L66-69)
```java
    private void recordHealthMetric(Health health) {
        final var status = health != null ? health.getStatus() : Status.UP;
        CLUSTER_UP.set(Status.UP.equals(status) ? 1 : 0);
    }
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicator.java (L93-121)
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
                .timeout(Duration.ofSeconds(5))
                .onErrorResume(e -> {
                    var status = Status.UNKNOWN;
                    // Connection issue can be caused by database being down, since the rest API service will become
                    // unavailable eventually
                    var rootCause = ExceptionUtils.getRootCause(e);
                    if (rootCause instanceof ConnectException || rootCause instanceof TimeoutException) {
                        status = Status.DOWN;
                    }

                    var statusMessage =
                            String.format("Network stake status is %s with error: %s", status, e.getMessage());
                    log.error(statusMessage);
                    return health(status, statusMessage);
                });
```

**File:** monitor/src/main/java/org/hiero/mirror/monitor/subscribe/rest/RestApiClient.java (L67-69)
```java
    public Mono<HttpStatusCode> getNetworkStakeStatusCode() {
        return webClientRestJava.get().uri("/network/stake").exchangeToMono(r -> Mono.just(r.statusCode()));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** monitor/src/test/java/org/hiero/mirror/monitor/health/SubscriberHealthIndicatorTest.java (L109-123)
```java
    @SneakyThrows
    @Test
    void restNetworkStakeTimeoutException() {
        when(transactionGenerator.scenarios()).thenReturn(Flux.just(publishScenario(1.0)));
        when(mirrorSubscriber.getSubscriptions()).thenReturn(Flux.just(subscribeScenario(1.0)));
        when(restApiClient.getNetworkStakeStatusCode())
                .thenReturn(Mono.delay(Duration.ofSeconds(6L)).thenReturn(HttpStatusCode.valueOf(200)));

        StepVerifier.withVirtualTime(() -> subscriberHealthIndicator.health())
                .thenAwait(Duration.ofSeconds(10L))
                .expectNextMatches(s -> s.getStatus() == Status.DOWN
                        && ((String) s.getDetails().get("reason")).contains("within 5000ms"))
                .expectComplete()
                .verify(Duration.ofSeconds(1L));
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

**File:** tools/k6/src/rest-java/test/networkStake.js (L1-17)
```javascript
// SPDX-License-Identifier: Apache-2.0

import http from 'k6/http';

import {isSuccess, RestJavaTestScenarioBuilder} from '../libex/common.js';

const urlTag = '/network/stake';

const {options, run, setup} = new RestJavaTestScenarioBuilder()
  .name('networkStake') // use unique scenario name among all tests
  .tags({url: urlTag})
  .request((testParameters) => {
    const url = `${testParameters['BASE_URL_PREFIX']}${urlTag}`;
    return http.get(url);
  })
  .check('Network stake OK', isSuccess)
  .build();
```
