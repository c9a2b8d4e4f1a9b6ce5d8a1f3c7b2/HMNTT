### Title
Unauthenticated `GET /api/v1/topics/{id}` Lacks Application-Level Rate Limiting, Enabling Distributed Griefing

### Summary
The `getTopic()` handler in `TopicController.java` is publicly accessible with no authentication and no rate limiting enforced at the application layer. Each invocation issues three independent database queries. An unprivileged attacker using multiple IP addresses or proxies faces no per-IP or global request throttle within the `rest-java` service, allowing sustained high-volume flooding that exhausts database connection pools and degrades availability for legitimate users.

### Finding Description
**Code location:** `rest-java/src/main/java/org/hiero/mirror/restjava/controller/TopicController.java`, lines 31–37.

```java
@GetMapping(value = "/{id}")
Topic getTopic(@PathVariable EntityIdNumParameter id) {
    var topic = topicService.findById(id.id());       // DB query 1
    var entity = entityService.findById(id.id());     // DB query 2
    var customFee = customFeeService.findById(id.id()); // DB query 3
    return topicMapper.map(customFee, entity, topic);
}
```

**Root cause:** The `rest-java` module registers only two servlet filters — `LoggingFilter` and `MetricsFilter` — neither of which enforces any rate limit or connection throttle. `RestJavaConfiguration` adds only an ETag filter and a Protobuf converter. `WebMvcConfiguration` adds only argument resolvers. There is no `bucket4j`, no Spring Security rate-limiting, and no IP-keyed throttle anywhere in the `rest-java` filter chain.

The `authHandler` middleware and its associated per-user limit enforcement exist exclusively in the Node.js `rest/` module (`rest/middleware/authHandler.js`), not in `rest-java`. The `web3/` module has a `ThrottleManagerImpl` with bucket4j, but it is scoped to `web3` contract-call endpoints only.

The Helm chart for `rest-java` includes a conditional `middleware.yaml` template, but it is gated on `global.middleware` being set and requires explicit operator configuration — it is not a guaranteed deployed control.

**Exploit flow:**
1. Attacker enumerates valid topic IDs (trivially sequential integers).
2. Attacker distributes requests across a botnet or rotating proxy pool, each IP sending requests to `GET /api/v1/topics/{id}`.
3. Because there is no per-IP or global rate limit in the application, every request is accepted and triggers three synchronous DB queries.
4. The database connection pool saturates; legitimate requests queue and time out.

**Why existing checks fail:** There are no existing checks in `rest-java` to fail — the filter chain contains only logging and metrics instrumentation. Any infrastructure-level rate limiting (e.g., Traefik middleware, cloud load balancer) is optional and operator-configured, not enforced by the application itself.

### Impact Explanation
Each `getTopic()` call issues three database reads. At modest scale (e.g., 1,000 req/s distributed across 50 IPs), this generates 3,000 DB queries per second. The shared PostgreSQL connection pool becomes the bottleneck, causing query queuing, timeout errors, and cascading failures across all `rest-java` endpoints. Legitimate users experience 503/504 responses. The impact is service-level availability degradation (griefing) with no economic cost to the attacker.

### Likelihood Explanation
The attack requires no credentials, no special knowledge, and no exploit tooling beyond a standard HTTP client and access to a proxy pool or botnet. Topic IDs are sequential integers, so valid IDs are trivially enumerable. The attack is repeatable indefinitely and is not self-limiting. Any actor motivated to disrupt the mirror node REST API can execute this with minimal resources.

### Recommendation
1. **Application-level rate limiting:** Integrate `bucket4j` (already used in `web3/`) or Spring's `resilience4j` rate limiter as a `OncePerRequestFilter` in `rest-java`, keyed on client IP (extracted from `X-Forwarded-For` with trusted-proxy validation).
2. **Global concurrency cap:** Configure a Tomcat/Jetty max-connections or a semaphore-based concurrency limiter for the `/api/v1/topics` path.
3. **Mandatory infrastructure controls:** Document and enforce that the Traefik/GCP rate-limiting middleware is required (not optional) for any public deployment of `rest-java`.
4. **Connection pool protection:** Set a DB query timeout and a maximum connection pool size with a queue limit so that pool exhaustion returns 429/503 quickly rather than cascading.

### Proof of Concept
```bash
# Distribute across multiple source IPs using a proxy list
# Step 1: Identify a valid topic ID (sequential, start from 1)
curl -s https://<mirror-node>/api/v1/topics/1

# Step 2: Flood from multiple IPs via proxy rotation
for i in $(seq 1 1000); do
  curl -s --proxy "http://proxy${i}:8080" \
    "https://<mirror-node>/api/v1/topics/$((RANDOM % 1000 + 1))" &
done
wait

# Step 3: Observe legitimate requests timing out
curl -v https://<mirror-node>/api/v1/topics/1
# Expected: 503 Service Unavailable or connection timeout
# due to exhausted DB connection pool
```

No authentication token, API key, or privileged access is required at any step. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** charts/hedera-mirror-rest-java/templates/middleware.yaml (L1-5)
```yaml
# SPDX-License-Identifier: Apache-2.0

{{ if and .Values.global.middleware .Values.middleware -}}
apiVersion: traefik.io/v1alpha1
kind: Middleware
```
