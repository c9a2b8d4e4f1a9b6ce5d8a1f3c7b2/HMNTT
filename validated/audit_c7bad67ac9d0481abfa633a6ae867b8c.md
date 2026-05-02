Based on my thorough code investigation, all technical claims in this report are verified against the actual codebase. Here is the audit result:

---

## Audit Report

## Title
Unauthenticated Endpoint `/api/v1/network/stake` Lacks Caching and Rate Limiting, Enabling Database Exhaustion via Repeated `findLatest()` Queries

## Summary
The public REST endpoint `GET /api/v1/network/stake` in the `rest-java` module unconditionally executes a native SQL query with a correlated subquery against the `network_stake` table on every request. No caching, rate limiting, or authentication is present in the application layer. An unprivileged attacker can flood this endpoint to exhaust the JDBC connection pool and degrade or deny service to all consumers of the mirror node REST API.

## Finding Description

**Verified code path:**

`NetworkController.getNetworkStake()` is a plain `@GetMapping("/stake")` with no authentication or throttle annotation: [1](#0-0) 

It delegates unconditionally to `NetworkServiceImpl.getLatestNetworkStake()`, which calls the repository with no caching layer: [2](#0-1) 

`NetworkStakeRepository.findLatest()` executes a native SQL query containing a correlated subquery (`select max(consensus_timestamp) from network_stake`) on every invocation: [3](#0-2) 

**Confirmed absence of mitigations:**

1. **No caching**: A grep for `@Cacheable`, `@EnableCaching`, and `CacheManager` across all of `rest-java/src/main/java/` returns zero matches. Although `spring-boot-starter-cache` is declared as a dependency, no cache configuration or annotations are present in the module. [4](#0-3) 

2. **No rate limiting**: The only throttle/rate-limit code in the `rest-java` module is scoped to `FeeEstimationService` (fee calculation logic), not to any HTTP endpoint. No `bucket4j`, `RateLimiter`, or equivalent is wired to the `/stake` route. [5](#0-4) 

3. **Filters perform no throttling**: `MetricsFilter` records byte metrics only, and `LoggingFilter` logs requests only — neither performs any request throttling or rejection. [6](#0-5) [7](#0-6) 

The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, `bucket4j`) exists only in the `web3` module and is not shared with `rest-java`. [8](#0-7) 

## Impact Explanation
Every HTTP request to `GET /api/v1/network/stake` causes two database operations: a `MAX()` aggregate scan and a row fetch on `network_stake`. At high request rates, this exhausts the JDBC connection pool shared by all `rest-java` endpoints, causing query queuing and timeouts. The realistic impact is **mirror node REST API unavailability** — the mirror node is read-only and does not participate in consensus, so the claim of impacting "transaction validators" is overstated, but API-level denial of service is achievable.

## Likelihood Explanation
The exploit requires zero privileges, zero authentication, and only a standard HTTP client. The endpoint path `/api/v1/network/stake` is publicly documented in the OpenAPI spec. [9](#0-8) 
The attack is trivially automatable with tools like `ab`, `wrk`, or a simple loop. No special knowledge beyond the public API path is required.

## Recommendation
1. **Add response caching**: Annotate `NetworkStakeRepository.findLatest()` with `@Cacheable` using a short TTL (e.g., 60 seconds). The `network_stake` table is updated at most once per staking period (daily), making this data highly cacheable. Enable `@EnableCaching` in a `rest-java` configuration class.
2. **Add rate limiting**: Introduce a rate-limiting filter or interceptor in the `rest-java` module (analogous to `ThrottleManagerImpl` in `web3`) applied to all public endpoints, or at minimum to `/api/v1/network/stake`.
3. **Infrastructure-level protection**: Deploy a reverse proxy or API gateway (e.g., HAProxy, Nginx, Traefik) with per-IP rate limiting in front of the `rest-java` service.

## Proof of Concept
```bash
# Flood the endpoint from a single client
wrk -t 10 -c 100 -d 30s http://<mirror-node-host>:8084/api/v1/network/stake
```
Each request triggers the correlated subquery in `NetworkStakeRepository.findLatest()`. At sufficient concurrency, the HikariCP connection pool is exhausted, causing subsequent requests (including to other endpoints sharing the same pool) to time out with `Connection is not available, request timed out`.

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

**File:** rest-java/build.gradle.kts (L32-32)
```text
    implementation("org.springframework.boot:spring-boot-starter-cache")
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/fee/FeeEstimationService.java (L42-72)
```java
public class FeeEstimationService {

    private final ExecutorComponent executor;
    private final FileDataRepository fileDataRepository;
    private final long feeScheduleFileId;
    private final FeeTopicStore feeTopicStore;
    private final FeeTokenStore feeTokenStore;
    private final AtomicLong lastFeeScheduleTimestamp;
    private final FeeManager feeManager;

    public FeeEstimationService(
            final FeeEstimationState feeEstimationState,
            final FileDataRepository fileDataRepository,
            final SystemEntity systemEntity,
            final FeeTopicStore feeTopicStore,
            final FeeTokenStore feeTokenStore) {
        this.fileDataRepository = fileDataRepository;
        this.feeScheduleFileId = systemEntity.simpleFeeScheduleFile().getId();
        this.feeTopicStore = feeTopicStore;
        this.feeTokenStore = feeTokenStore;
        this.lastFeeScheduleTimestamp = new AtomicLong(Long.MIN_VALUE);

        this.executor = TRANSACTION_EXECUTORS.newExecutorComponent(
                feeEstimationState,
                Map.of(),
                null,
                Set.of(),
                new AppEntityIdFactory(FeeEstimationFeeContext.CONFIGURATION));
        executor.stateNetworkInfo().initFrom(feeEstimationState);
        this.feeManager = Objects.requireNonNull(executor.feeManager());
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/MetricsFilter.java (L49-58)
```java
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
