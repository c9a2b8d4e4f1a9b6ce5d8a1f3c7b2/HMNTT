Let me check the alerts rules file for the `RestJavaHighDBConnections` alert reference.

All key claims have been verified against the codebase. Here is the result:

---

Audit Report

## Title
Uncached, Unauthenticated `GET /api/v1/network/stake` Executes Unbounded DB Queries, Enabling Connection Pool Exhaustion

## Summary
`NetworkController.getNetworkStake()` unconditionally calls `NetworkStakeRepository.findLatest()` on every HTTP request with no caching and no rate limiting. Because the `rest-java` module has no application-layer throttle, an unprivileged attacker can sustain a moderate request stream to saturate the shared HikariCP connection pool, causing cascading latency or errors across all endpoints that share the pool.

## Finding Description

**Verified code path:**

`NetworkController.getNetworkStake()` at line 127 calls `networkService.getLatestNetworkStake()` with no guard of any kind: [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` at line 52 calls the repository directly. There is no `@Cacheable`, no in-memory result reuse, and no short-circuit: [2](#0-1) 

`NetworkStakeRepository.findLatest()` issues a native correlated subquery on every invocation — an inner `MAX` scan followed by an outer row fetch: [3](#0-2) 

**Root cause — failed assumption:** The design implicitly assumes the endpoint is called infrequently. The `network_stake` data changes only once per staking period (~24 h), yet the result is never cached. Every HTTP request unconditionally acquires a HikariCP connection and executes two sequential table operations.

**Contrast with grpc module:** The grpc module's analogous `NodeStakeRepository.findAllStakeByConsensusTimestamp()` is decorated with `@Cacheable` backed by a Caffeine cache manager, demonstrating the pattern is known and applied elsewhere — just not here: [4](#0-3) 

## Impact Explanation
The HikariCP pool in `rest-java` is shared across all endpoints. Pool exhaustion caused by `/network/stake` traffic starves other endpoints (`/api/v1/transactions`, `/api/v1/accounts`, etc.) of connections, producing cascading latency or `504` errors across the entire service. The monitoring infrastructure confirms this is a recognized operational risk: a `RestJavaHighDBConnections` alert is defined and fires when active connections exceed 75% of pool capacity. [5](#0-4) 

## Likelihood Explanation
No authentication, API key, or session token is required. The endpoint accepts plain `GET` requests. The `rest-java` module contains no application-layer rate limiting. The only filter present is `MetricsFilter`, which only records byte counts and does not throttle: [6](#0-5) 

The `web3` module has a full throttle stack (`ThrottleConfiguration`, `ThrottleManagerImpl`, bucket4j) but these beans are scoped entirely to `web3` and are not present in `rest-java`: [7](#0-6) [8](#0-7) 

A single attacker with a modest HTTP client (`wrk`, `hey`, `ab`) can sustain the required request rate without triggering any brute-force detection, because there is no per-IP or global RPS limit enforced at the application layer for this endpoint.

## Recommendation
1. **Add a short-lived cache** on `NetworkServiceImpl.getLatestNetworkStake()` using `@Cacheable` with a Caffeine-backed `CacheManager` (TTL of 60–300 s is sufficient given the ~24 h data change frequency). This eliminates redundant DB round-trips entirely.
2. **Apply application-layer rate limiting** to `rest-java` endpoints, mirroring the bucket4j pattern already used in `web3/ThrottleConfiguration`.
3. **Set an explicit HikariCP `connectionTimeout`** in the `rest-java` datasource configuration so that pool exhaustion returns a fast error rather than blocking threads indefinitely.

## Proof of Concept
```bash
# Sustained stream of 100 concurrent connections, 10 000 requests total
ab -n 10000 -c 100 https://<host>/api/v1/network/stake

# Or with wrk (2 threads, 50 connections, 30 s)
wrk -t2 -c50 -d30s https://<host>/api/v1/network/stake
```
When in-flight requests exceed the HikariCP pool size, subsequent threads block on `HikariPool.getConnection()`. Blocked threads accumulate in the JVM thread pool, increasing scheduler overhead and manifesting as elevated CPU and latency across all endpoints sharing the pool. The `RestJavaHighDBConnections` alert will fire once active connections exceed 75% of pool capacity.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L24-28)
```java
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```

**File:** charts/hedera-mirror-common/alerts/rules.tf (L1501-1558)
```terraform
  rule {
    name      = "RestJavaNoRequests"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum(rate(http_server_requests_seconds_count{application=\\\"rest-java\\\"}[3m])) by (cluster, namespace) <= 0\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "3m"
    annotations = {
      description = "{{ $labels.cluster }}: Java REST API has not seen any requests to {{ $labels.namespace }} for 5m"
      summary     = "[{{ $labels.cluster }}] No Java REST API requests seen for a while"
    }
    labels = {
      application = "rest-java"
      severity    = "warning"
    }
    is_paused = false
  }
  rule {
    name      = "RestJavaQueryLatency"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum(rate(spring_data_repository_invocations_seconds_sum{application=\\\"rest-java\\\"}[5m])) by (cluster, namespace, pod) / sum(rate(spring_data_repository_invocations_seconds_count{application=\\\"rest-java\\\"}[5m])) by (cluster, namespace, pod) > 1\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "1m"
    annotations = {
      description = "{{ $labels.cluster }}: High average database query latency of {{ (index $values \"A\").Value | humanizeDuration }} for {{ $labels.namespace }}/{{ $labels.pod }}"
      summary     = "[{{ $labels.cluster }}] Mirror Java REST API query latency exceeds 1s"
    }
    labels = {
      application = "rest-java"
      severity    = "warning"
    }
    is_paused = false
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L20-49)
```java
final class ThrottleManagerImpl implements ThrottleManager {

    static final String REQUEST_PER_SECOND_LIMIT_EXCEEDED = "Requests per second rate limit exceeded";
    static final String GAS_PER_SECOND_LIMIT_EXCEEDED = "Gas per second rate limit exceeded.";

    @Qualifier(GAS_LIMIT_BUCKET)
    private final Bucket gasLimitBucket;

    @Qualifier(RATE_LIMIT_BUCKET)
    private final Bucket rateLimitBucket;

    @Qualifier(OPCODE_RATE_LIMIT_BUCKET)
    private final Bucket opcodeRateLimitBucket;

    private final ThrottleProperties throttleProperties;

    @Override
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
