### Title
Missing Rate Limiting in `getNftAllowances()` Enables Connection Pool Starvation DoS

### Summary
The `getNftAllowances()` method in `NftAllowanceServiceImpl` is reachable via a fully public, unauthenticated HTTP endpoint with zero rate limiting in the `rest-java` module. An attacker can flood the endpoint with concurrent requests, exhausting the HikariCP database connection pool (default: 10 connections) and starving all other API consumers. The `web3` module has an explicit `ThrottleManagerImpl`/`ThrottleConfiguration` rate-limiting stack; `rest-java` has no equivalent.

### Finding Description
**Code path:**
- Controller: `AllowancesController.getNftAllowances()` — `rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java:57-83`
- Service: `NftAllowanceServiceImpl.getNftAllowances()` — `rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java:21-31`

Every request to `GET /api/v1/accounts/{id}/allowances/nfts` unconditionally calls:
1. `entityService.lookup(request.getAccountId())` — for alias/EVM-address `accountId` values this issues a DB query via `EntityRepository`
2. `repository.findAll(request, id)` — always issues a DB query against the `nft_allowance` table

**Root cause:** The `rest-java` module registers only `LoggingFilter` and `MetricsFilter` in its filter chain (`RestJavaConfiguration`, `LoggingFilter`, `MetricsFilter`). Neither enforces any request rate limit. `WebMvcConfiguration` adds only argument resolvers. `RestJavaProperties` contains only response-header configuration. There is no `ThrottleManager`, no `Bucket4j` bean, and no Spring Security filter in this module.

**Contrast with `web3`:** `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` defines `rateLimitBucket`, `gasLimitBucket`, and `opcodeRateLimitBucket` beans; `ThrottleManagerImpl.throttle()` enforces them on every contract-call request. No analogous protection exists for `rest-java`.

**Connection pool:** `CommonConfiguration` creates a `HikariDataSource` from `spring.datasource.hikari` properties. No `application.yml` is present in `rest-java/src/main/resources/` (only `banner.txt`), so HikariCP defaults apply: `maximumPoolSize = 10`. With 10 or more concurrent slow queries (e.g., large `limit=100` scans on a populated `nft_allowance` table), the pool is fully occupied and every subsequent request blocks until `connectionTimeout` (default 30 s) expires, returning a 503.

### Impact Explanation
- **Availability:** Complete denial of service for all `rest-java` API endpoints sharing the same HikariCP pool. Because the pool is shared, exhausting it via the NFT allowances endpoint also blocks unrelated endpoints (accounts, tokens, transactions, etc.).
- **Severity: High.** The mirror node is public infrastructure. Downtime directly affects wallets, explorers, and dApps that depend on it for balance/allowance queries.

### Likelihood Explanation
- **Preconditions:** None. No account, API key, or authentication is required.
- **Feasibility:** A single attacker with a modest botnet (or even a single machine using async HTTP) can sustain thousands of concurrent requests. The `limit` parameter accepts up to `MAX_LIMIT` (checked via `@Max(MAX_LIMIT)` in the controller), making each query potentially expensive.
- **Repeatability:** Continuous; the attacker simply keeps the flood running.

### Recommendation
1. **Immediate:** Add a Bucket4j-based rate-limiting filter to `rest-java` mirroring the pattern in `web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java` — a global requests-per-second bucket enforced in a `OncePerRequestFilter` before the controller is reached.
2. **Per-IP limiting:** The global bucket should be complemented by per-source-IP limiting (using `request.getRemoteAddr()`) to prevent a single client from consuming the entire budget.
3. **Pool sizing:** Explicitly configure `spring.datasource.hikari.maximum-pool-size` in `rest-java`'s configuration to a value appropriate for expected concurrency, and set `connection-timeout` to fail fast rather than queue indefinitely.
4. **Query timeout:** Ensure `spring.datasource.hikari.connection-timeout` and a JDBC statement timeout are set so that runaway queries release connections promptly.

### Proof of Concept
```bash
# Flood with 500 concurrent requests using different numeric accountIds
# No authentication required
seq 1 500 | xargs -P 500 -I{} \
  curl -s -o /dev/null \
  "https://<mirror-node-host>/api/v1/accounts/0.0.{}/allowances/nfts?limit=100"
```
**Expected result:** After the first ~10 requests occupy all HikariCP connections, subsequent requests queue and eventually time out. Legitimate users receive HTTP 503 (`QueryTimeoutException` → `SERVICE_UNAVAILABLE` per `GenericControllerAdvice.queryTimeout()`) or hang until the pool timeout fires. The node remains degraded for the duration of the flood. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/NftAllowanceServiceImpl.java (L21-31)
```java
    public Collection<NftAllowance> getNftAllowances(NftAllowanceRequest request) {

        var ownerOrSpenderId = request.getOwnerOrSpenderIds();
        var token = request.getTokenIds();

        checkOwnerSpenderParamValidity(ownerOrSpenderId, token);

        var id = entityService.lookup(request.getAccountId());

        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/AllowancesController.java (L57-83)
```java
    @GetMapping(value = "/nfts")
    NftAllowancesResponse getNftAllowances(
            @PathVariable EntityIdParameter id,
            @RequestParam(name = ACCOUNT_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] accountIds,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "asc") Sort.Direction order,
            @RequestParam(defaultValue = "true") boolean owner,
            @RequestParam(name = TOKEN_ID, required = false) @Size(max = 2) EntityIdRangeParameter[] tokenIds) {
        var field = owner ? NFT_ALLOWANCE.SPENDER : NFT_ALLOWANCE.OWNER;
        var request = NftAllowanceRequest.builder()
                .accountId(id)
                .isOwner(owner)
                .limit(limit)
                .order(order)
                .ownerOrSpenderIds(new Bound(accountIds, true, ACCOUNT_ID, field))
                .tokenIds(new Bound(tokenIds, false, TOKEN_ID, NFT_ALLOWANCE.TOKEN_ID))
                .build();

        var serviceResponse = service.getNftAllowances(request);
        var allowances = nftAllowanceMapper.map(serviceResponse);

        var sort = Sort.by(order, ACCOUNT_ID, TOKEN_ID);
        var pageable = PageRequest.of(0, limit, sort);
        var links = linkFactory.create(allowances, pageable, EXTRACTORS.get(owner));

        return new NftAllowancesResponse().allowances(allowances).links(links);
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

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L60-95)
```java
    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @Lazy
    DataSource dataSource(
            DataSourceProperties dataSourceProperties,
            HikariConfig hikariConfig,
            DatabaseWaiter databaseWaiter,
            ObjectProvider<JdbcConnectionDetails> detailsProvider) {

        var jdbcUrl = dataSourceProperties.determineUrl();
        var username = dataSourceProperties.determineUsername();
        var password = dataSourceProperties.determinePassword();

        final var connectionDetails = detailsProvider.getIfAvailable();
        if (connectionDetails != null) {
            jdbcUrl = connectionDetails.getJdbcUrl();
            username = connectionDetails.getUsername();
            password = connectionDetails.getPassword();
        }

        databaseWaiter.waitForDatabase(jdbcUrl, username, password);

        final var config = new HikariConfig();
        hikariConfig.copyStateTo(config);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);

        return new HikariDataSource(config);
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
