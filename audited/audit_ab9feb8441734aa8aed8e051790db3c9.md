### Title
Unbounded In-Memory Response Buffering via Unprotected `ShallowEtagHeaderFilter` Enables Heap-Exhaustion DoS on `/api/*` Endpoints

### Summary
The `etagFilter()` bean in `RestJavaConfiguration.java` registers Spring's `ShallowEtagHeaderFilter` across all `/api/*` URL patterns with no response-size cap and no rate limiting. `ShallowEtagHeaderFilter` internally wraps every response in a `ContentCachingResponseWrapper` that accumulates the full response body in a JVM heap `ByteArrayOutputStream` before computing the ETag. Because the `rest-java` module has zero rate-limiting or connection-throttling infrastructure (unlike the `web3` module), an unauthenticated attacker can open many concurrent connections to large-response history endpoints and exhaust JVM heap, causing an OutOfMemoryError DoS.

### Finding Description

**Exact code path:**

`rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, lines 42–46:

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

`ShallowEtagHeaderFilter` (Spring Framework) wraps the `HttpServletResponse` in a `ContentCachingResponseWrapper`. Every byte written by the controller is accumulated in an internal `ByteArrayOutputStream` on the JVM heap for the lifetime of the request. Only after the full response is written does the filter compute the MD5 ETag, compare it to `If-None-Match`, and flush (or discard) the buffer. There is no `setWriteWeakETag`, no `setMaxCacheSize`, and no response-size guard applied here.

**Root cause / failed assumption:**
The configuration assumes that either (a) responses are small enough that concurrent buffering is harmless, or (b) an upstream layer (reverse proxy, API gateway) will enforce connection/rate limits before requests reach the JVM. Neither assumption is enforced at the code level in this module.

**Why existing checks fail:**
- The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` rate-limiting stack lives entirely in the `web3` module and is not wired into `rest-java` at all.
- `rest-java` has no `application.yaml` / `application.properties` (only `banner.txt` exists in resources), so no custom `server.tomcat.max-connections`, `server.tomcat.threads.max`, or `server.max-http-request-header-size` limits are set — Tomcat defaults apply (up to 8 192 accepted connections, 200 worker threads).
- `LoggingFilter` and `MetricsFilter` in `rest-java` are purely observational; they impose no admission control.
- No `@RateLimiter`, no servlet filter, and no Spring Security layer in `rest-java` rejects or throttles high-volume unauthenticated callers.

### Impact Explanation
Each concurrent request to a large-response endpoint (e.g., a paginated transaction or account history list) holds a full copy of the serialized JSON/Protobuf response body on the heap simultaneously. With Tomcat's default 200 worker threads all serving maximum-page-size responses concurrently, heap pressure can reach hundreds of megabytes to gigabytes depending on configured page sizes. An `OutOfMemoryError` in the JVM kills the process or causes severe GC thrashing, making all Hashgraph history endpoints unavailable to legitimate clients — a direct denial-of-service against the integrity and availability of the mirror node's historical record API.

### Likelihood Explanation
The attack requires no credentials, no special protocol knowledge, and no exploit tooling beyond a standard HTTP load generator (e.g., `wrk`, `ab`, `hey`). The attacker simply needs to discover the public `/api/*` base path (documented in the project) and issue concurrent GET requests with large `limit=` parameters. The absence of any application-level rate limiting in `rest-java` means the attack is repeatable and sustainable until the process is restarted or an operator intervenes externally.

### Recommendation
1. **Add a response-size guard to the filter** — subclass `ShallowEtagHeaderFilter` and override `isEligibleForEtag()` to skip buffering (return `false`) when the response `Content-Length` exceeds a configurable threshold (e.g., 512 KB).
2. **Add rate limiting to `rest-java`** — introduce a `FilterRegistrationBean` backed by Bucket4j (already a dependency in `web3`) that enforces a per-IP or global requests-per-second cap on `/api/*`, mirroring the pattern in `ThrottleConfiguration`.
3. **Set explicit Tomcat limits** — add `server.tomcat.max-connections`, `server.tomcat.threads.max`, and `server.tomcat.accept-count` in `rest-java` application configuration to bound the number of concurrently buffered responses.
4. **Deploy an upstream rate-limiting reverse proxy** — enforce connection and request-rate limits at the ingress layer (nginx `limit_req`, Envoy, or an API gateway) as a defense-in-depth measure independent of application code.

### Proof of Concept

```bash
# Precondition: rest-java service running, /api/* endpoints publicly reachable, no upstream proxy rate limiting
# Step 1: Identify a large-response endpoint (e.g., transactions list with max page size)
ENDPOINT="http://<host>:<port>/api/v1/transactions?limit=100"

# Step 2: Flood with concurrent requests using wrk (200 concurrent connections, 30 seconds)
wrk -t 16 -c 200 -d 30s "$ENDPOINT"

# Step 3: Each of the 200 concurrent Tomcat threads runs ShallowEtagHeaderFilter,
#         buffering a full JSON response (~50-200 KB each) in heap simultaneously.
#         With 200 threads × 200 KB = ~40 MB per wave; sustained load causes
#         heap growth, GC pressure, and eventual OOM / service unavailability.

# Expected result: JVM OutOfMemoryError or severe GC thrashing;
#                  legitimate clients receive 503 / connection refused.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L1-26)
```java
// SPDX-License-Identifier: Apache-2.0

package org.hiero.mirror.restjava.config;

import com.google.protobuf.ExtensionRegistry;
import com.google.protobuf.Message;
import jakarta.annotation.PostConstruct;
import java.io.IOException;
import java.util.ArrayList;
import lombok.RequiredArgsConstructor;
import org.hiero.mirror.restjava.jooq.DomainRecordMapperProvider;
import org.springframework.boot.convert.ApplicationConversionService;
import org.springframework.boot.jooq.autoconfigure.DefaultConfigurationCustomizer;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.format.support.FormattingConversionService;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.protobuf.ProtobufHttpMessageConverter;
import org.springframework.web.filter.ShallowEtagHeaderFilter;

@Configuration
@RequiredArgsConstructor
class RestJavaConfiguration {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L42-46)
```java
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
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

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleProperties.java (L13-35)
```java
@ConfigurationProperties("hiero.mirror.web3.throttle")
@Data
@Validated
public class ThrottleProperties {

    private static final long GAS_SCALE_FACTOR = 10_000L;

    @Min(0)
    @Max(100)
    private float gasLimitRefundPercent = 100;

    @Min(21_000)
    @Max(10_000_000_000_000L)
    private long gasPerSecond = 7_500_000_000L;

    @Min(1)
    private long opcodeRequestsPerSecond = 1;

    @NotNull
    private List<RequestProperties> request = List.of();

    @Min(1)
    private long requestsPerSecond = 500;
```
