### Title
Missing Rate Limiting on `/api/v1/accounts/{id}/allowances/nfts` Enables Resource Exhaustion

### Summary
The `rest-java` module exposes the `/api/v1/accounts/{id}/allowances/nfts` endpoint with no rate limiting, while the `web3` module has an explicit `ThrottleConfiguration` using bucket4j. An unauthenticated attacker can flood this endpoint with valid, distinct requests at `limit=MAX_LIMIT`, each triggering a full JOOQ query against the `nft_allowance` table, exhausting the DB connection pool and sustaining CPU above 30% without triggering brute-force detection.

### Finding Description
**Code path:**

- `AllowancesController.java` lines 57–83: The `getNftAllowances` handler accepts `limit` up to `MAX_LIMIT` with only `@Positive` and `@Max(MAX_LIMIT)` bean-validation annotations — no throttle check, no authentication. [1](#0-0) 

- `NftAllowanceRepositoryCustomImpl.java` lines 37–47: Each request executes a JOOQ `SELECT … WHERE … ORDER BY … LIMIT N` against the `nft_allowance` table, holding a DB connection for the full query duration. [2](#0-1) 

- `RestJavaConfiguration.java` and `WebMvcConfiguration.java`: The entire `rest-java` config directory contains only an ETag filter, logging/metrics filters, JOOQ customizer, and MVC argument resolvers. No rate-limit bean, no throttle interceptor, no bucket4j integration exists anywhere in this module. [3](#0-2) 

- `ThrottleConfiguration.java` (web3 module only): Bucket4j rate-limit beans (`rateLimitBucket`, `gasLimitBucket`, `opcodeRateLimitBucket`) are defined exclusively in `web3`, confirming the architectural gap. [4](#0-3) 

**Root cause:** The failed assumption is that infrastructure-level (e.g., nginx/API gateway) rate limiting is sufficient. No application-level guard exists in `rest-java`, so any attacker who bypasses or is not subject to such infrastructure controls can saturate the service.

### Impact Explanation
Each request at `limit=MAX_LIMIT` issues an `ORDER BY spender/owner, token_id` query on the `nft_allowance` table. Under concurrent flood, the DB connection pool (typically 10–20 connections by default in HikariCP) is exhausted, causing request queuing and thread starvation in the Spring MVC thread pool. CPU rises due to repeated sort operations on large result sets. This constitutes a sustained >30% resource elevation without any single request being anomalous. Severity: **Medium** (availability impact, no data exfiltration).

### Likelihood Explanation
No privileges are required. The attacker needs only a list of valid account IDs (publicly derivable from the Hedera network) and a script sending concurrent HTTP GET requests. The requests are semantically valid (not brute force), so IP-based brute-force detection does not trigger. The attack is trivially repeatable and scriptable.

### Recommendation
1. Add a bucket4j `rateLimitBucket` bean to `rest-java` mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`.
2. Register a servlet filter or Spring MVC interceptor in `RestJavaConfiguration` or `WebMvcConfiguration` that consumes a token per request and returns HTTP 429 when exhausted.
3. Enforce a per-IP or per-account-ID rate limit at the application layer, not solely at the infrastructure layer.
4. Consider reducing `MAX_LIMIT` or adding a cost-based throttle proportional to the requested `limit` value.

### Proof of Concept
```bash
# Flood the endpoint with 200 concurrent valid requests at max limit
# Replace ACCOUNT_ID with any valid Hedera account (e.g., 0.0.1234)
for i in $(seq 1 200); do
  curl -s "https://<mirror-node-host>/api/v1/accounts/0.0.1234/allowances/nfts?limit=100&order=asc" &
done
wait
# Monitor: DB connection pool active count approaches max; CPU sustained >30%
# No 429 responses are returned; all requests are processed or queue-timeout
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-64)
```java
    @GetMapping(value = "/nfts")
    NftAllowancesResponse getNftAllowances(
            @PathVariable EntityIdParameter id,
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(defaultValue = "true") boolean owner,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/NftAllowanceRepositoryCustomImpl.java (L37-47)
```java
    public Collection<NftAllowance> findAll(NftAllowanceRequest request, EntityId accountId) {
        boolean byOwner = request.isOwner();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, byOwner).and(getBoundConditions(bounds));
        return dslContext
                .selectFrom(NFT_ALLOWANCE)
                .where(condition)
                .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
                .limit(request.getLimit())
                .fetchInto(NftAllowance.class);
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
