### Title
Unauthenticated Thread-Pool Exhaustion via Synchronous Blocking DB Calls in `getTopic()` Without Rate Limiting or Query Timeouts

### Summary
`getTopic()` in `TopicController` makes three sequential synchronous blocking JDBC calls with no query timeouts and no application-level rate limiting. Any unauthenticated attacker can flood the public endpoint with concurrent requests, causing each Tomcat worker thread to block indefinitely on slow database queries, exhausting the bounded thread pool and rendering the node unresponsive.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 32–37:

```java
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());      // blocking JDBC
    var entity = entityService.findById(id.id());    // blocking JDBC
    var customFee = customFeeService.findById(id.id()); // blocking JDBC
    return topicMapper.map(customFee, entity, topic);
}
```

Each call delegates to a Spring Data JPA `CrudRepository.findById()` — a fully synchronous, blocking JDBC operation:
- `TopicServiceImpl.findById()` → `topicRepository.findById(id.getId())`
- `EntityServiceImpl.findById()` → `entityRepository.findById(id.getId())`
- `CustomFeeServiceImpl.findById()` → `customFeeRepository.findById(id.getId())`

**Root cause — two compounding missing controls:**

1. **No application-level rate limiting.** The `web3` module has `ThrottleManagerImpl` backed by bucket4j (`ThrottleConfiguration`, `rateLimitBucket`, `gasLimitBucket`). The `rest-java` module has no equivalent. `RestJavaConfiguration` registers only a `ShallowEtagHeaderFilter` and a `ProtobufHttpMessageConverter` — no throttle filter exists for `/api/v1/topics/{id}`.

2. **No query timeouts.** The `web3` module has `HibernateConfiguration` with a `StatementInspector` that throws `QueryTimeoutException` when `requestTimeout` is exceeded. The `rest-java` module has no such `StatementInspector`, no `@Transactional(timeout=...)`, and no JDBC socket/statement timeout configured for these service methods.

**Why existing checks fail:**

- The GCP `backendPolicy` (`maxRatePerEndpoint: 250`) is an optional infrastructure-level setting (`gateway.gcp.enabled: true` is the default, but it is infrastructure-dependent and not an application-level control). It is not present in all deployments and does not protect against slow-loris-style holding of already-admitted connections.
- `GenericControllerAdvice` handles `QueryTimeoutException` with a 503, but no timeout is ever set to trigger it in `rest-java`.
- The `LoggingFilter` only logs; it performs no throttling.
- The endpoint requires no authentication (`@GetMapping` with no security annotation).

### Impact Explanation
The `rest-java` application runs on a standard Spring MVC / Tomcat stack (not reactive). Tomcat's default thread pool is bounded (200 threads). Each admitted request occupies one thread for the full duration of all three blocking DB calls. Under database load — which the attacker can induce by flooding the endpoint itself — each request can block for tens of seconds. Once all 200 threads are occupied, new requests queue and eventually time out, making the node completely unresponsive to all API traffic. Targeting 30%+ of mirror nodes simultaneously (which serve the same public API) achieves the described network-processing impact threshold.

### Likelihood Explanation
The attack requires zero privileges, zero authentication, and only a standard HTTP client. The endpoint is publicly routable (the ingress rule `/api/v1/topics/(\d+\.){0,2}\d+$` is explicitly exposed). The attacker needs only to send a sustained flood of concurrent GET requests to `/api/v1/topics/{id}` with any valid or invalid topic ID. Because `topicService.findById()` throws `EntityNotFoundException` (not found) before the other two calls only when the topic is absent — but all three calls execute sequentially for existing topics — the attacker can use any known topic ID to maximize per-request DB work. The attack is trivially repeatable and scriptable.

### Recommendation
1. **Add application-level rate limiting to `rest-java`** analogous to `web3`'s `ThrottleManagerImpl` / `ThrottleConfiguration`, applied as a servlet filter on `/api/v1/**`.
2. **Add query timeouts** either via a `StatementInspector` (mirroring `web3`'s `HibernateConfiguration`) or via `@Transactional(timeout = N)` on the service methods, so slow queries are interrupted and threads are released.
3. **Parallelize the three DB calls** (e.g., using `CompletableFuture`) to reduce per-request thread hold time from 3× query latency to 1× max query latency.
4. **Consider virtual threads** (`spring.threads.virtual.enabled=true`) as a partial mitigation to reduce the cost of blocking, though this does not eliminate DB connection pool exhaustion.

### Proof of Concept
```bash
# Flood the endpoint with 500 concurrent requests (no auth needed)
seq 1 500 | xargs -P 500 -I{} \
  curl -s "https://<mirror-node-host>/api/v1/topics/0.0.1" &

# Simultaneously observe thread pool saturation:
# tomcat_threads_busy_threads{application="rest-java"} → approaches max
# New requests begin returning 503 or timing out
# Repeat across 30%+ of mirror node instances for network-level impact
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7) [9](#0-8)

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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L41-46)
```java
    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-47)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/GenericControllerAdvice.java (L120-124)
```java
    @ExceptionHandler
    private ResponseEntity<Object> queryTimeout(final QueryTimeoutException e, final WebRequest request) {
        log.error("Query timed out: {}", e.getMessage());
        return handleExceptionInternal(e, null, null, SERVICE_UNAVAILABLE, request);
    }
```

**File:** charts/hedera-mirror-rest-java/values.yaml (L56-59)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
```
