### Title
Unauthenticated Request Flood Exhausts Shared HikariCP Connection Pool via Unthrottled `GET /api/v1/topics/{id}`

### Summary
`TopicController.getTopic()` issues three sequential, uncached database queries per request with no application-level rate limiting in the `rest-java` module. An unprivileged attacker can flood this endpoint to exhaust the shared HikariCP connection pool, causing all database-dependent requests — including topic custom-fee lookups — to time out or queue indefinitely, forcing downstream clients to rely on stale cached fee data for transaction fee decisions.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 32–37:

```java
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());      // DB query 1
    var entity = entityService.findById(id.id());    // DB query 2
    var customFee = customFeeService.findById(id.id()); // DB query 3
    return topicMapper.map(customFee, entity, topic);
}
```

Each of the three service implementations (`TopicServiceImpl`, `EntityServiceImpl`, `CustomFeeServiceImpl`) performs a direct, synchronous JPA repository call with no `@Cacheable` annotation and no result caching of any kind. [1](#0-0) [2](#0-1) [3](#0-2) 

**Root cause — no rate limiting in `rest-java`:**

The throttle/rate-limiting infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, bucket4j) exists exclusively in the `web3` module and is wired only to `ContractCallRequest` flows. [4](#0-3) 

The `rest-java` module registers only a `LoggingFilter` and a `ShallowEtagHeaderFilter` — neither imposes any per-IP or global request rate limit. [5](#0-4) [6](#0-5) 

The `Cache-Control: public, max-age=5` response header is a client-side hint only; it does not reduce server-side DB load. [7](#0-6) 

**Exploit flow:**

1. Attacker sends a continuous flood of `GET /api/v1/topics/{id}` requests (no authentication required, no rate gate).
2. Each request consumes up to 3 HikariCP connections simultaneously (sequential blocking calls).
3. The shared pool is exhausted; new requests queue or time out with `QueryTimeoutException` → HTTP 503.
4. Legitimate clients querying topic custom fees receive 503 errors and fall back to locally cached (potentially stale) fee schedules.
5. Stale fee data causes clients to submit transactions with incorrect fees, resulting in rejected transactions or overpayment.

### Impact Explanation

The direct impact is a complete availability denial of the `GET /api/v1/topics/{id}` endpoint and, due to the shared HikariCP pool, collateral degradation of all other `rest-java` endpoints. The monitoring alert `RestJavaHighDBConnections` fires only after the pool exceeds 75% utilization — it is reactive, not preventive. [8](#0-7) 

The secondary financial impact arises because topic custom fees (fixed, fractional, royalty) returned by this endpoint are used by clients to calculate transaction fees before submission. Unavailability forces clients to use stale data, which can cause fee underpayment (transaction rejection) or overpayment (fund loss).

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero knowledge beyond the public API path. The endpoint is unauthenticated and publicly documented. A single attacker with a modest botnet or even a single high-throughput HTTP client can sustain enough concurrent requests to saturate a typical HikariCP pool (default max 10 connections). The attack is trivially repeatable and automatable.

### Recommendation

1. **Add rate limiting to `rest-java`**: Introduce a bucket4j or Resilience4j `RateLimiter` filter in the `rest-java` module, mirroring the pattern already used in `web3/ThrottleConfiguration`, applied globally or per-IP via a `OncePerRequestFilter`.
2. **Add service-layer caching**: Annotate `TopicServiceImpl.findById`, `EntityServiceImpl.findById`, and `CustomFeeServiceImpl.findById` with `@Cacheable` (e.g., Caffeine with a short TTL matching the existing `max-age=5` response header) to eliminate redundant DB hits for repeated lookups of the same topic.
3. **Isolate connection pools**: Use a separate HikariCP pool for the topic/fee endpoints so that a flood cannot starve other critical paths.
4. **Deploy infrastructure-level rate limiting**: Enforce per-IP request limits at the ingress/load-balancer layer as a defense-in-depth measure.

### Proof of Concept

```bash
# Flood the endpoint with 500 concurrent connections, unlimited requests
# No authentication required
ab -n 100000 -c 500 https://<mirror-node-host>/api/v1/topics/0.0.1234

# Or with wrk:
wrk -t 16 -c 500 -d 60s https://<mirror-node-host>/api/v1/topics/0.0.1234
```

**Expected result:** Within seconds, HikariCP pool utilization reaches 100%; subsequent requests to any `rest-java` endpoint return HTTP 503 (`QueryTimeoutException`). Legitimate clients querying topic fees receive errors and fall back to stale cached fee schedules. [9](#0-8)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TopicServiceImpl.java (L19-21)
```java
    public Topic findById(EntityId id) {
        return topicRepository.findById(id.getId()).orElseThrow(() -> new EntityNotFoundException("Topic not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L24-27)
```java
    public Entity findById(EntityId id) {
        return entityRepository.findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Entity not found"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/CustomFeeServiceImpl.java (L19-23)
```java
    public CustomFee findById(EntityId id) {
        return customFeeRepository
                .findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Custom fee for entity not found"));
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
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

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/TopicControllerTest.java (L93-95)
```java
                assertThat(response.getHeaders().getAccessControlAllowOrigin()).isEqualTo("*");
                assertThat(response.getHeaders().getCacheControl()).isEqualTo("public, max-age=5");
            };
```

**File:** charts/hedera-mirror-common/alerts/rules.tf (L1382-1411)
```terraform
  rule {
    name      = "RestJavaHighDBConnections"
    condition = "A"

    data {
      ref_id = "A"

      relative_time_range {
        from = 600
        to   = 0
      }

      datasource_uid = "grafanacloud-prom"
      model          = "{\"editorMode\":\"code\",\"expr\":\"sum(hikaricp_connections_active{application=\\\"rest-java\\\"}) by (cluster, namespace, pod) / sum(hikaricp_connections_max{application=\\\"rest-java\\\"}) by (cluster, namespace, pod) > 0.75\",\"instant\":true,\"intervalMs\":1000,\"legendFormat\":\"__auto\",\"maxDataPoints\":43200,\"range\":false,\"refId\":\"A\"}"
    }

    no_data_state  = "NoData"
    exec_err_state = "Error"
    for            = "5m"
    annotations = {
      description = "{{ $labels.cluster }}: {{ $labels.namespace }}/{{ $labels.pod }} is using {{ (index $values \"A\").Value | humanizePercentage }} of available database connections"
      summary     = "[{{ $labels.cluster }}] Mirror Java REST API database connection utilization exceeds 75%"
    }
    labels = {
      application = "rest-java"
      area        = "resource"
      severity    = "critical"
    }
    is_paused = false
  }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L120-124)
```java
    @ExceptionHandler
    private ResponseEntity<Object> queryTimeout(final QueryTimeoutException e, final WebRequest request) {
        log.error("Query timed out: {}", e.getMessage());
        return handleExceptionInternal(e, null, null, SERVICE_UNAVAILABLE, request);
    }
```
