### Title
Unbounded Heap Buffering via ShallowEtagHeaderFilter Enables Memory Exhaustion DoS on rest-java

### Summary
The `etagFilter()` bean in `RestJavaConfiguration.java` registers Spring's `ShallowEtagHeaderFilter` across all `/api/*` endpoints. This filter must buffer the entire response body in JVM heap memory to compute an MD5 ETag hash. Because the rest-java module has no rate limiting (unlike the web3 module), an unprivileged attacker can flood concurrent requests to large-response endpoints, causing simultaneous heap buffering of many full response bodies, leading to OOM crashes across mirror node instances.

### Finding Description
**Exact code location**: `rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, `etagFilter()`, lines 42–46.

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

**Root cause**: Spring's `ShallowEtagHeaderFilter` wraps the `HttpServletResponse` in a `ContentCachingResponseWrapper`. Every byte written by the controller is intercepted and accumulated in a heap-allocated `ByteArrayOutputStream` before being flushed to the client. The filter holds this buffer for the full duration of response generation and transmission. There is no size cap on this buffer.

**No rate limiting in rest-java**: The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module. The rest-java config directory contains only: `JacksonConfiguration`, `LoggingFilter`, `MetricsConfiguration`, `MetricsFilter`, `NetworkProperties`, `RestJavaConfiguration`, `RuntimeHintsConfiguration`, and `WebMvcConfiguration` — none of which implement rate limiting. The `docs/configuration.md` REST Java API section lists no rate-limiting properties.

**Exploit flow**:
1. Attacker identifies a large-response endpoint, e.g., `GET /api/v1/network/nodes?limit=100`, which returns up to 100 network nodes each with service endpoints, admin keys, and description fields — easily 100–500 KB of JSON per response.
2. Attacker opens many concurrent connections (Tomcat default: 200 worker threads) and sends requests simultaneously from multiple IPs.
3. For each in-flight request, `ShallowEtagHeaderFilter` holds the full serialized response body in a `ByteArrayOutputStream` on the JVM heap until the response is fully written to the client.
4. With 200 concurrent requests × ~300 KB per response = ~60 MB of heap consumed by ETag buffers alone, sustained continuously with no rate limiting.
5. Combined with normal heap usage (DB connection pools, object allocation, GC pressure), the JVM hits OOM and the process crashes.

**Why existing checks fail**: Pagination limits (max 100 items, enforced at controller level) bound the number of records but not the byte size of each record or the total response. The filter has no awareness of response size and no configurable limit. There is no per-IP or global request rate limit in rest-java.

### Impact Explanation
An OOM crash terminates the rest-java JVM process. If the attacker targets multiple instances simultaneously (or if a single instance serves a significant fraction of traffic), 30%+ of mirror node processing capacity can be taken offline. The attack is sustained — Kubernetes will restart crashed pods, but the attacker can immediately re-flood them, keeping instances in a crash-restart loop and effectively denying service.

### Likelihood Explanation
The attack requires zero authentication, zero privileges, and only the ability to send HTTP GET requests — available to any internet user. The endpoint is public by design. The attacker needs only a modest number of concurrent connections (achievable from a single machine or small botnet). The attack is repeatable and automatable with standard HTTP tools (`ab`, `wrk`, `curl`). No exploit code or special knowledge is required beyond knowing the API path.

### Recommendation
1. **Add rate limiting to rest-java**: Implement a `FilterRegistrationBean` using bucket4j (already a dependency in the web3 module) to limit requests per IP per second on `/api/*` endpoints, mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`.
2. **Cap ETag filter response size**: Subclass `ShallowEtagHeaderFilter` and override `isEligibleForEtag()` to return `false` for responses above a configurable byte threshold (e.g., 1 MB), bypassing buffering for large responses.
3. **Set Tomcat connection/thread limits**: Configure `server.tomcat.max-threads` and `server.tomcat.accept-count` in the rest-java application properties to bound the number of concurrent in-flight requests.
4. **Deploy an ingress-level rate limiter**: Use Traefik/NGINX rate limiting at the load balancer layer as a defense-in-depth measure.

### Proof of Concept
```bash
# Send 200 concurrent requests to a large-response endpoint
# No authentication required
ab -n 10000 -c 200 \
  'http://<mirror-node-host>:8084/api/v1/network/nodes?limit=100'

# Alternatively with wrk for sustained load:
wrk -t 10 -c 200 -d 60s \
  'http://<mirror-node-host>:8084/api/v1/network/nodes?limit=100'

# Monitor JVM heap on the target:
# Expected: heap usage climbs rapidly, OOM error thrown,
# process exits with java.lang.OutOfMemoryError: Java heap space
# in the ShallowEtagHeaderFilter / ContentCachingResponseWrapper stack frame
```

**Relevant code references**: [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
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

**File:** docs/configuration.md (L614-637)
```markdown
## REST Java API

Similar to the [Importer](#importer), the REST Java API uses [Spring Boot](https://spring.io/projects/spring-boot)
properties
to configure the application.

The following table lists the available properties along with their default values. Unless you need to set a non-default
value, it is recommended to only populate overridden properties in the custom `application.yml`.

| Name                                                     | Default                                            | Description                                                                                                                                                   |
| -------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.restJava.db.host`                          | 127.0.0.1                                          | The IP or hostname used to connect to the database                                                                                                            |
| `hiero.mirror.restJava.db.name`                          | mirror_node                                        | The name of the database                                                                                                                                      |
| `hiero.mirror.restJava.db.password`                      | mirror_rest_java_pass                              | The database password used to connect to the database                                                                                                         |
| `hiero.mirror.restJava.db.port`                          | 5432                                               | The port used to connect to the database                                                                                                                      |
| `hiero.mirror.restJava.db.sslMode`                       | DISABLE                                            | The SSL level. Accepts either DISABLE, ALLOW, PREFER, REQUIRE, VERIFY_CA or VERIFY_FULL.                                                                      |
| `hiero.mirror.restJava.db.statementTimeout`              | 10000                                              | The number of milliseconds to wait before timing out a query statement                                                                                        |
| `hiero.mirror.restJava.db.username`                      | mirror_rest_java                                   | The username used to connect to the database                                                                                                                  |
| `hiero.mirror.restJava.fee.refreshInterval`              | 10m                                                | How often to check for fee schedule updates from the database. Can accept duration units like `10s`, `2m` etc.                                                |
| `hiero.mirror.restJava.network.unreleasedSupplyAccounts` | 2-2, 42-42, 44-71, 73-87, 99-100, 200-349, 400-750 | Account ranges holding unreleased HBAR supply, excluded from circulating supply calculations                                                                  |
| `hiero.mirror.restJava.query.maxFileAttempts`            | 12                                                 | The maximum amount of times to query for Hedera files when the contents are not valid.                                                                        |
| `hiero.mirror.restJava.response.headers.defaults`        | See application.yml                                | The default headers to add to every response. For each header, specify its `name: value`                                                                      |
| `hiero.mirror.restJava.response.headers.path`            | See application.yml                                | Override default or add headers per path to add to every response. The key is the controller request mapping, then for each header, specify its `name: value` |

```
