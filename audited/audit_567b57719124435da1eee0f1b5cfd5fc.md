### Title
Unbounded In-Memory Response Buffering via `ShallowEtagHeaderFilter` Enables Heap Exhaustion (Griefing DoS)

### Summary
The `etagFilter()` bean in `RestJavaConfiguration` registers a stock `ShallowEtagHeaderFilter` across all `/api/*` endpoints with no buffer-size cap. Spring's `ShallowEtagHeaderFilter` wraps every response in a `ContentCachingResponseWrapper` backed by an unbounded `ByteArrayOutputStream`, holding the full serialized response body in heap until the MD5 ETag is computed and the body is flushed. Because the `rest-java` module has no rate-limiting or connection-throttling (unlike the `web3` module), an unprivileged attacker can open many concurrent requests to force the JVM to hold multiple full response buffers simultaneously, causing sustained heap pressure and potential OOM.

### Finding Description

**Exact code location:**
`rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java`, lines 42–46:

```java
@Bean
FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
    final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
    filterRegistrationBean.addUrlPatterns("/api/*");
    return filterRegistrationBean;
}
```

**Root cause:**
Spring's `ShallowEtagHeaderFilter.doFilterInternal()` unconditionally wraps the `HttpServletResponse` in a `ContentCachingResponseWrapper`. Every byte written by the controller accumulates in an internal `ByteArrayOutputStream` with no maximum size. Only after the entire response body is written does the filter compute the MD5 hash, emit the `ETag` header, and flush the buffer to the wire. During this window, the full response body occupies heap for the lifetime of the request.

The filter is instantiated with `new ShallowEtagHeaderFilter()` — no `writeWeakETag`, no custom `isEligibleForEtag` override, and critically **no buffer size limit** — and is applied to every URL under `/api/*`.

**No rate limiting in rest-java:**
The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module. The `rest-java` config directory contains only `LoggingFilter`, `MetricsFilter`, `WebMvcConfiguration`, and `RestJavaConfiguration` — none of which impose per-IP or global request-rate limits. No Tomcat `maxConnections`/`maxThreads` overrides appear in any `rest-java` YAML.

**Exploit flow:**
1. Attacker identifies a high-yield endpoint, e.g. `GET /api/v1/accounts/{id}/hooks?limit=100` (max allowed by `@Max(MAX_LIMIT)` at line 86 of `HooksController`).
2. Attacker opens N concurrent HTTP connections (no authentication required) and issues the same request on each.
3. For each request, `ShallowEtagHeaderFilter` allocates a `ContentCachingResponseWrapper` buffer; the controller serializes up to 100 records into it.
4. All N buffers live in heap simultaneously until each request completes.
5. With Tomcat's default thread pool (200 threads), up to 200 × `response_size` bytes are pinned in heap at once.

**Why existing checks are insufficient:**
- Pagination caps (`MAX_LIMIT = 100`) bound per-response record count but not byte size; hook storage entries can contain arbitrary binary key/value data.
- The `MetricsFilter` records response size after the fact but imposes no limit.
- The `LoggingFilter` in `rest-java` does not buffer responses at all — it only logs.
- There is no `Cache-Control: no-store` or conditional-request short-circuit that would prevent the filter from buffering on every fresh request.

### Impact Explanation
An attacker with no credentials can sustain heap pressure on the `rest-java` JVM, triggering frequent full GC cycles, increasing tail latency for all users, and — under sufficient concurrency — causing `OutOfMemoryError` and service crash. This matches the stated scope of "griefing with no economic damage to any user on the network" at medium severity: availability is degraded or lost, but no funds or on-chain state are affected.

### Likelihood Explanation
The attack requires only the ability to send HTTP GET requests to a public API endpoint — no authentication, no special headers, no knowledge of internal state. It is trivially scriptable (`ab`, `wrk`, `hey`, or a simple shell loop). The absence of any rate-limiting layer in `rest-java` means the attacker faces no server-side friction. The attack is repeatable and can be sustained indefinitely.

### Recommendation
1. **Add a buffer-size guard:** Subclass `ShallowEtagHeaderFilter` and override `isEligibleForEtag()` to return `false` for responses above a configurable byte threshold (e.g., 512 KB), or override `generateETagHeaderValue()` to skip buffering when `ContentCachingResponseWrapper.getContentAsByteArray().length` exceeds the threshold.
2. **Add rate limiting to rest-java:** Port the `bucket4j`-based `ThrottleConfiguration` pattern from the `web3` module, or place a reverse proxy (nginx/Envoy) with connection and request-rate limits in front of `rest-java`.
3. **Consider weak ETags or response-level caching:** If ETag freshness is not critical, use a `Last-Modified` header instead, which requires no response buffering.

### Proof of Concept
```bash
# Requires: a running rest-java instance and a known account ID with hooks
ACCOUNT=0.0.12345
URL="http://localhost:8084/api/v1/accounts/${ACCOUNT}/hooks?limit=100"

# Open 200 concurrent requests (matches default Tomcat thread pool)
seq 200 | xargs -P200 -I{} curl -s -o /dev/null "$URL" &

# Monitor heap via JMX or:
watch -n1 'curl -s http://localhost:8084/actuator/metrics/jvm.memory.used | python3 -m json.tool'
```
Expected result: `jvm.memory.used` for the heap climbs proportionally to concurrency and does not release until GC runs; under sustained load, GC overhead increases and eventually `OutOfMemoryError` is thrown. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L24-46)
```java
@Configuration
@RequiredArgsConstructor
class RestJavaConfiguration {

    private final FormattingConversionService mvcConversionService;

    @PostConstruct
    void initialize() {
        // Register application converters to use case-insensitive string to enum converter.
        ApplicationConversionService.addApplicationConverters(mvcConversionService);
    }

    @Bean
    DefaultConfigurationCustomizer configurationCustomizer(DomainRecordMapperProvider domainRecordMapperProvider) {
        return c -> c.set(domainRecordMapperProvider).settings().withRenderSchema(false);
    }

    @Bean
    FilterRegistrationBean<ShallowEtagHeaderFilter> etagFilter() {
        final var filterRegistrationBean = new FilterRegistrationBean<>(new ShallowEtagHeaderFilter());
        filterRegistrationBean.addUrlPatterns("/api/*");
        return filterRegistrationBean;
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L86-87)
```java
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "desc") Sort.Direction order) {
```
