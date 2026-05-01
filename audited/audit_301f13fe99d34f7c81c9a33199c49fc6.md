### Title
Unauthenticated Cross-Account Hook Storage Enumeration via Unrestricted BETWEEN Query

### Summary
The `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoint in the rest-java module performs no authentication or authorization check on the `ownerId` path parameter. Any unauthenticated external caller can supply an arbitrary victim `ownerId` and retrieve that account's complete hook storage. No rate limiting exists in the rest-java module for this endpoint, making iterative enumeration trivially repeatable.

### Finding Description

**Exact code path:**

`HooksController.getHookStorage()` accepts `ownerId` as a plain path variable with no identity verification: [1](#0-0) 

It builds a `HookStorageRequest` and delegates to `HookServiceImpl.getHookStorage()`: [2](#0-1) 

Which calls the repository with the caller-supplied `ownerId` directly: [3](#0-2) 

**Root cause — no access control in rest-java:**

The `WebMvcConfiguration` registers only argument resolvers: [4](#0-3) 

`RestJavaConfiguration` registers only an ETag filter and a Protobuf converter — no security filter chain: [5](#0-4) 

A `grep` for `SecurityConfig`, `HttpSecurity`, `@PreAuthorize`, `@Secured`, or any rate-limiter in `rest-java/**/*.java` returns **no matches**. The throttle/rate-limit infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module: [6](#0-5) 

It is not wired into rest-java at all.

**Point-query BETWEEN path:**

When a caller passes `key=gte:0xABC...&key=lte:0xABC...`, the controller sets both `lowerBound` and `upperBound` to the same value: [7](#0-6) 

This produces a BETWEEN predicate with equal bounds — a point lookup — routed to `findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse`. The attacker can repeat this for any candidate key with no credential requirement and no rate gate.

**Simpler bulk-read path (no iteration needed):**

Without any `key` parameter, `lowerBound` defaults to `0x00…00` and `upperBound` to `0xFF…FF`: [8](#0-7) 

This returns all non-deleted storage entries for the victim account in paginated form (up to `MAX_LIMIT = 100` per page), with a `next` link for continuation — no key guessing required.

### Impact Explanation

Any unauthenticated internet user can read the complete hook storage of any account by supplying that account's numeric ID in the URL. Hook storage holds arbitrary key/value data written by smart-contract hooks; depending on what contracts store there (e.g., balances, access-control state, configuration), full disclosure constitutes a confidentiality breach. The `deleted = false` filter means only live, active entries are returned, making the leak directly actionable.

### Likelihood Explanation

Preconditions are minimal: the attacker needs only a valid `ownerId` (account IDs are sequential integers, publicly enumerable via `/api/v1/accounts`) and a valid `hookId` (also enumerable via `/api/v1/accounts/{id}/hooks`). No credentials, tokens, or special network position are required. The attack is fully automatable with standard HTTP tooling and is repeatable without bound.

### Recommendation

1. **Enforce caller identity** on the hooks storage endpoint. Require the caller to authenticate (e.g., via a signed Hedera transaction ID or an operator API key) and verify that the authenticated identity matches the requested `ownerId`, or that the caller holds an explicit delegation.
2. **Add rate limiting** to the rest-java module for `/api/v1/accounts/*/hooks/*/storage`, mirroring the bucket4j throttle already present in the `web3` module.
3. **Scope the repository query** so that even if authentication is bypassed, the DB-level predicate enforces ownership (it already does — the fix must be at the HTTP layer).

### Proof of Concept

```
# Step 1: discover victim account IDs (public endpoint)
curl https://mirror-node/api/v1/accounts

# Step 2: discover hookIds for victim account 0.0.1234
curl https://mirror-node/api/v1/accounts/0.0.1234/hooks

# Step 3: dump all hook storage for victim (no credentials)
curl "https://mirror-node/api/v1/accounts/0.0.1234/hooks/5678/storage?limit=100&order=asc"
# Follow "links.next" to paginate through all entries.

# Step 4 (point-query BETWEEN variant):
curl "https://mirror-node/api/v1/accounts/0.0.1234/hooks/5678/storage?key=gte:0xDEADBEEF...&key=lte:0xDEADBEEF..."
# Returns the single entry for that exact key if it exists, with no auth and no rate limit.
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L104-113)
```java
    @GetMapping("/{hookId}/storage")
    ResponseEntity<HooksStorageResponse> getHookStorage(
            @PathVariable EntityIdParameter ownerId,
            @PathVariable @Min(0) long hookId,
            @RequestParam(name = KEY, required = false, defaultValue = "") @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    List<SlotRangeParameter> keys,
            @RequestParam(name = TIMESTAMP, required = false, defaultValue = "") @Size(max = 2)
                    TimestampParameter[] timestamps,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Direction order) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L167-168)
```java
        var lowerBound = MIN_KEY_BYTES;
        var upperBound = MAX_KEY_BYTES;
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L170-184)
```java
        for (final var key : keys) {
            final byte[] value = key.value();

            if (key.hasLowerBound()) {
                if (key.operator() == RangeOperator.EQ) {
                    keyFilters.add(value);
                } else if (Arrays.compareUnsigned(value, lowerBound) > 0) {
                    lowerBound = value;
                }
            } else if (key.hasUpperBound()) {
                if (Arrays.compareUnsigned(value, upperBound) < 0) {
                    upperBound = value;
                }
            }
        }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L56-69)
```java
    public HookStorageResult getHookStorage(HookStorageRequest request) {
        if (request.isHistorical()) {
            return getHookStorageChange(request);
        }

        final var ownerId = entityService.lookup(request.getOwnerId());
        final var page = request.getPageRequest();
        final var keys = request.getKeys();

        if (keys.isEmpty()) {
            final var hookStorage = hookStorageRepository.findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
                    ownerId.getId(), request.getHookId(), request.getKeyLowerBound(), request.getKeyUpperBound(), page);

            return new HookStorageResult(ownerId, hookStorage);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/HookStorageRepository.java (L16-17)
```java
    List<HookStorage> findByOwnerIdAndHookIdAndKeyBetweenAndDeletedIsFalse(
            long ownerId, long hookId, byte[] fromKey, byte[] toKey, Pageable pageable);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/WebMvcConfiguration.java (L17-31)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
final class WebMvcConfiguration implements WebMvcConfigurer {

    private final RequestParameterArgumentResolver requestParameterArgumentResolver;

    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> resolvers) {
        resolvers.add(requestParameterArgumentResolver);
    }

    @Override
    public void addFormatters(FormatterRegistry registry) {
        registry.addConverter(String.class, EntityIdParameter.class, EntityIdParameter::valueOf);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/config/RestJavaConfiguration.java (L36-46)
```java
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
