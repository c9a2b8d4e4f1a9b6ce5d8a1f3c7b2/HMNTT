### Title
Uncached, Unauthenticated `GET /api/v1/network/stake` Executes Unbounded DB Queries, Enabling Connection Pool Exhaustion

### Summary
`NetworkStakeRepository.findLatest()` executes a native correlated-subquery SQL statement on every HTTP request with no caching and no rate limiting in the `rest-java` module. An unprivileged external user can sustain a moderate stream of `GET /api/v1/network/stake` requests to saturate the HikariCP connection pool, causing thread queuing, elevated JVM thread-hold time, and measurable CPU increase across the service.

### Finding Description

**Exact code path:**

`NetworkController.getNetworkStake()` (line 127) calls `networkService.getLatestNetworkStake()` with no guard: [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` (line 52) calls the repository directly with no `@Cacheable` or any in-memory result reuse: [2](#0-1) 

`NetworkStakeRepository.findLatest()` issues a native correlated subquery on every invocation: [3](#0-2) 

**Root cause — failed assumption:** The design assumes that the `network_stake` table is queried infrequently. The data changes only once per staking period (~24 h), yet the result is never cached. Every HTTP request unconditionally acquires a HikariCP connection and executes two sequential table operations (the inner `MAX` scan and the outer row fetch).

**Exploit flow:**
1. Attacker sends a sustained stream of `GET /api/v1/network/stake` requests (e.g., 50–200 req/s from multiple IPs or a single IP with keep-alive).
2. Each request acquires a HikariCP connection, runs the correlated subquery, and holds the connection until the result is returned.
3. When concurrent in-flight requests exceed the pool size (HikariCP default: 10), subsequent threads block on `HikariPool.getConnection()` waiting for a free slot.
4. Blocked threads accumulate in the JVM thread pool, increasing thread-hold time and scheduler overhead, which manifests as elevated CPU.

### Impact Explanation

The HikariCP pool for `rest-java` is shared across all endpoints. Pool exhaustion caused by `/network/stake` traffic starves other endpoints (e.g., `/api/v1/transactions`, `/api/v1/accounts`) of connections, causing cascading latency or `504` errors across the entire service. The monitoring infrastructure confirms this is a recognized risk — a `RestJavaHighDBConnections` alert fires when active connections exceed 75% of pool capacity: [4](#0-3) 

Because the `network_stake` data changes only once per day, every DB round-trip is redundant work that could be eliminated with a short-lived cache.

### Likelihood Explanation

No authentication, API key, or session token is required. The endpoint accepts plain `GET` requests. The `rest-java` module contains no rate-limiting equivalent to the `web3` module's `ThrottleManagerImpl`/`ThrottleConfiguration` — those classes are scoped entirely to `web3`: [5](#0-4) 

No such throttle bean or filter exists in `rest-java`. A single attacker with a modest HTTP client (e.g., `wrk`, `hey`, or `ab`) can sustain the required request rate without triggering any brute-force detection, because there is no per-IP or global RPS limit enforced at the application layer for this endpoint.

### Recommendation

1. **Add `@Cacheable`** to `NetworkStakeRepository.findLatest()` or to `NetworkServiceImpl.getLatestNetworkStake()` with a TTL of 60–300 seconds (matching the staking period cadence). This eliminates the DB round-trip for the vast majority of requests. The `grpc` module's `NodeStakeRepository` already demonstrates this pattern with `@Cacheable(cacheManager = NODE_STAKE_CACHE, ...)`. [6](#0-5) 

2. **Add application-level rate limiting** to the `rest-java` module for public endpoints, analogous to the `web3` throttle infrastructure.

3. **Tune HikariCP** `maximumPoolSize` and `connectionTimeout` to fail fast rather than queue indefinitely when the pool is saturated.

### Proof of Concept

```bash
# Requires: wrk (https://github.com/wg/wrk)
# Target: rest-java service, no credentials needed

wrk -t8 -c100 -d300s http://<rest-java-host>/api/v1/network/stake
```

**Expected result:** After pool saturation (active connections ≥ `maximumPoolSize`), Hikari pending-connection metrics rise, JVM thread count climbs, and CPU usage increases measurably. Other endpoints on the same service begin returning errors or timing out. The `RestJavaHighDBConnections` Prometheus alert fires within 5 minutes.

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/NetworkController.java (L126-130)
```java
    @GetMapping("/stake")
    NetworkStakeResponse getNetworkStake() {
        final var networkStake = networkService.getLatestNetworkStake();
        return networkStakeMapper.map(networkStake);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L52-56)
```java
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

**File:** charts/hedera-mirror-rest-java/values.yaml (L211-221)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/NodeStakeRepository.java (L23-28)
```java
    // An empty map may be cached, indicating the node_stake table is empty
    @Cacheable(cacheManager = NODE_STAKE_CACHE, cacheNames = CACHE_NAME)
    default Map<Long, Long> findAllStakeByConsensusTimestamp(long consensusTimestamp) {
        return findAllByConsensusTimestamp(consensusTimestamp).stream()
                .collect(Collectors.toUnmodifiableMap(NodeStake::getNodeId, NodeStake::getStake));
    }
```
