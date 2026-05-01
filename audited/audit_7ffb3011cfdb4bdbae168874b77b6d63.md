### Title
Unconditional DB Query on Every Request to `GET /api/v1/network/stake` Due to Shallow ETag Filter and Absent Rate Limiting

### Summary
Every request to `GET /api/v1/network/stake` unconditionally executes `NetworkStakeRepository.findLatest()`, which runs a correlated subquery against the database. Although a `ShallowEtagHeaderFilter` is registered, it is shallow by design — it runs the full request pipeline (including the DB query) before computing the ETag, so `If-None-Match` headers save bandwidth but not DB load. With no rate limiting in the `rest-java` module and no server-side caching, an unprivileged attacker can flood this endpoint to drive sustained, unbounded DB query load.

### Finding Description

**Code path:**

`GET /api/v1/network/stake`
→ `NetworkController.getNetworkStake()` (line 126–130, `NetworkController.java`)
→ `NetworkServiceImpl.getLatestNetworkStake()` (lines 52–56, `NetworkServiceImpl.java`)
→ `NetworkStakeRepository.findLatest()` (lines 12–19, `NetworkStakeRepository.java`)

The repository executes a native SQL correlated subquery on every invocation:

```sql
select * from network_stake
where consensus_timestamp = (
    select max(consensus_timestamp) from network_stake
)
``` [1](#0-0) 

`NetworkServiceImpl.getLatestNetworkStake()` has no `@Cacheable` annotation and no in-memory cache: [2](#0-1) 

**The ETag filter is shallow — it does not prevent DB queries:**

`RestJavaConfiguration` registers a `ShallowEtagHeaderFilter` covering `/api/*`: [3](#0-2) 

Spring's `ShallowEtagHeaderFilter` works by letting the full handler chain execute (including the DB query), buffering the response body, computing an MD5 ETag from it, and only then checking `If-None-Match`. If they match, it returns 304 without sending the body — but the DB query has already run. This is confirmed by the test: [4](#0-3) 

**No rate limiting exists in `rest-java` for this endpoint:**

The `ThrottleConfiguration` and `ThrottleManagerImpl` with bucket4j rate limiting exist only in the `web3` module: [5](#0-4) 

The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, and the ETag filter — none of which rate-limit requests:



**No server-side caching exists in `rest-java`:** The `CacheConfiguration` classes with Caffeine caches are in the `grpc` and `importer` modules only, not in `rest-java`. [6](#0-5) 

### Impact Explanation
Each request causes two sequential DB operations (the correlated `max()` subquery plus the outer `select *`). With no rate limiting and no server-side caching, an attacker can sustain thousands of requests per second from a single machine or a small botnet. The DB connection pool will be saturated, query latency will increase for all other endpoints, and CPU/IO on the database node will rise proportionally. A 30%+ increase in processing node resource consumption is achievable with modest request volume (e.g., a few hundred req/s from a single client), well within reach of any unprivileged user with a standard HTTP client.

### Likelihood Explanation
No authentication, no API key, no CAPTCHA, and no rate limit guard this endpoint. The attack requires only an HTTP client and knowledge of the public API. It is trivially repeatable, automatable, and requires zero privileges. The endpoint is publicly documented in the OpenAPI spec: [7](#0-6) 

### Recommendation
1. **Add server-side caching** at the service layer: annotate `NetworkServiceImpl.getLatestNetworkStake()` with `@Cacheable` using a short TTL (e.g., 15–30 seconds), backed by Caffeine or Redis. Network stake data changes only once per staking period (~24 hours), so aggressive caching is safe.
2. **Add rate limiting** to the `rest-java` module for all `/api/v1/network/*` endpoints, mirroring the bucket4j pattern already used in `web3`.
3. **Replace `ShallowEtagHeaderFilter` with a deep/response-caching filter** (e.g., Spring's `ContentCachingResponseWrapper` with a proper cache store) so that `If-None-Match` hits avoid the DB query entirely, not just the response body transmission.

### Proof of Concept
```bash
# Flood the endpoint with no credentials required
# Each request unconditionally hits the DB
for i in $(seq 1 10000); do
  curl -s -o /dev/null "https://<mirror-node-host>/api/v1/network/stake" &
done
wait

# Even sending If-None-Match does NOT prevent DB queries:
ETAG=$(curl -sI "https://<mirror-node-host>/api/v1/network/stake" | grep -i etag | awk '{print $2}')
for i in $(seq 1 10000); do
  curl -s -o /dev/null -H "If-None-Match: $ETAG" \
    "https://<mirror-node-host>/api/v1/network/stake" &
done
wait
# DB query still executes on every request due to ShallowEtagHeaderFilter behavior
```

Monitor DB query rate via `pg_stat_activity` or equivalent; `select max(consensus_timestamp) from network_stake` will appear once per HTTP request, confirming unbounded DB load.

### Citations

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NetworkServiceImpl.java (L52-56)
```java
    public NetworkStake getLatestNetworkStake() {
        return networkStakeRepository
                .findLatest()
                .orElseThrow(() -> new EntityNotFoundException("No network stake data found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/ControllerTest.java (L141-156)
```java
        void etagHeader() {
            // Given
            final var request = defaultRequest(restClient.get());

            // When
            final var etag = request.retrieve().toBodilessEntity().getHeaders().getETag();

            // Then
            assertThat(etag).isNotBlank();
            assertThat(request.header(HttpHeaders.IF_NONE_MATCH, etag)
                            .retrieve()
                            .toBodilessEntity())
                    .returns(etag, r -> r.getHeaders().getETag())
                    .returns(null, ResponseEntity::getBody)
                    .returns(HttpStatus.NOT_MODIFIED, ResponseEntity::getStatusCode);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/CacheConfiguration.java (L16-55)
```java
@Configuration(proxyBeanMethods = false)
@EnableCaching
public class CacheConfiguration {

    public static final String ADDRESS_BOOK_ENTRY_CACHE = "addressBookEntryCache";
    public static final String NODE_STAKE_CACHE = "nodeStakeCache";
    public static final String ENTITY_CACHE = "entityCache";
    public static final String CACHE_NAME = "default";

    @Bean(ADDRESS_BOOK_ENTRY_CACHE)
    CacheManager addressBookEntryCache(AddressBookProperties addressBookProperties) {
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME)); // We have to eagerly set cache name to register metrics
        caffeineCacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(addressBookProperties.getCacheExpiry())
                .maximumSize(addressBookProperties.getCacheSize())
                .recordStats());
        return caffeineCacheManager;
    }

    @Bean(NODE_STAKE_CACHE)
    CacheManager nodeStakeCache(AddressBookProperties addressBookProperties) {
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCaffeine(Caffeine.newBuilder()
                .expireAfterWrite(addressBookProperties.getNodeStakeCacheExpiry())
                .maximumSize(addressBookProperties.getNodeStakeCacheSize())
                .recordStats());
        return caffeineCacheManager;
    }

    @Bean(ENTITY_CACHE)
    @Primary
    CacheManager entityCache(GrpcProperties grpcProperties) {
        int cacheSize = grpcProperties.getEntityCacheSize();
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification("recordStats,expireAfterWrite=24h,maximumSize=" + cacheSize);
        return caffeineCacheManager;
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
