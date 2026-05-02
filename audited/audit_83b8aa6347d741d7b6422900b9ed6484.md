### Title
Unauthenticated Triple-Query Fan-Out with No Rate Limiting or Server-Side Caching on GET /api/v1/topics/{id}

### Summary
Every call to `getTopic()` unconditionally fires three sequential database queries with no server-side caching and no rate limiting in the `rest-java` module. An unauthenticated attacker can flood the endpoint with concurrent requests, multiplying database read load by 3× per request and degrading response times for legitimate users.

### Finding Description

**Exact code path:**

`TopicController.getTopic()` at lines 32–36 issues three independent, sequential repository calls per HTTP request:

```
topicService.findById(id.id())     → topicRepository.findById()
entityService.findById(id.id())    → entityRepository.findById()
customFeeService.findById(id.id()) → customFeeRepository.findById()
``` [1](#0-0) 

**No server-side caching:** `TopicServiceImpl`, `EntityServiceImpl`, and `CustomFeeServiceImpl` all call their repositories directly with no `@Cacheable` or equivalent annotation. [2](#0-1) [3](#0-2) [4](#0-3) 

**No rate limiting in rest-java:** The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists exclusively in the `web3` module and is not wired into the `rest-java` module at all. [5](#0-4) 

**Root cause:** The failed assumption is that a downstream caching proxy (hinted by the `Cache-Control: public, max-age=5` response header) will absorb repeated requests. This is an infrastructure-level hint only — the server processes every request that reaches it, and the header can be bypassed by sending `Cache-Control: no-cache` or `Pragma: no-cache` in the request, or by varying the `Accept` / other headers. [6](#0-5) 

### Impact Explanation
Each concurrent request to `GET /api/v1/topics/{id}` consumes three database connections/read operations. An attacker sending N concurrent requests forces 3N simultaneous DB reads. Under sustained load this exhausts the database connection pool, increases query latency for all users, and can cause cascading timeouts across the mirror node. The impact is limited to availability degradation (no data mutation, no economic loss), consistent with the "Medium griefing" classification.

### Likelihood Explanation
No authentication, API key, or IP-based rate limit is required. Any external user with network access can issue unlimited requests using standard HTTP tooling (`curl`, `ab`, `wrk`, etc.). The attack is trivially repeatable, requires no special knowledge, and is not detectable until DB load spikes. The `Cache-Control` header only helps if a correctly configured caching reverse proxy sits in front; a direct deployment or cache-bypass headers eliminate that mitigation entirely.

### Recommendation
1. **Add server-side caching** on `TopicServiceImpl.findById`, `EntityServiceImpl.findById`, and `CustomFeeServiceImpl.findById` using Spring's `@Cacheable` with a short TTL (e.g., 5 seconds, matching the existing `Cache-Control` hint).
2. **Add rate limiting** to the `rest-java` module equivalent to the `web3` `ThrottleConfiguration` — a per-IP or global token-bucket limiter applied via a servlet filter or Spring interceptor.
3. **Parallelize the three queries** (e.g., using `CompletableFuture`) so that even without caching, a single request consumes one unit of wall-clock DB time instead of three sequential round-trips, reducing latency amplification.

### Proof of Concept
```bash
# Flood the endpoint with 500 concurrent requests (no auth required)
# Replace 0.0.1000 with any valid topic ID
ab -n 5000 -c 500 http://<mirror-node-host>/api/v1/topics/0.0.1000

# Bypass any upstream cache by forcing revalidation
for i in $(seq 1 1000); do
  curl -s -H "Cache-Control: no-cache" \
       http://<mirror-node-host>/api/v1/topics/0.0.1000 &
done
wait
# Each of the 1000 requests triggers 3 DB queries = 3000 DB reads
# Monitor DB connection pool exhaustion and query latency spike
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java (L32-37)
```java
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

**File:** rest-java/src/test/java/org/hiero/mirror/restjava/controller/TopicControllerTest.java (L93-95)
```java
                assertThat(response.getHeaders().getAccessControlAllowOrigin()).isEqualTo("*");
                assertThat(response.getHeaders().getCacheControl()).isEqualTo("public, max-age=5");
            };
```
