### Title
Unauthenticated DoS via Uncached, Unthrottled DB Lookups in `EntityServiceImpl.lookup()` Through EVM Address and Alias Formats

### Summary
`EntityServiceImpl.lookup()` in `rest-java` performs a live database query for every EVM address or alias `EntityIdParameter` without caching negative results and without any rate limiting. An unprivileged attacker can flood the `GET /api/v1/accounts/{ownerId}/hooks` and `GET /api/v1/accounts/{ownerId}/hooks/{hookId}/storage` endpoints with valid-format but non-existent EVM addresses or aliases, triggering a DB query per request, exhausting the HikariCP connection pool, and denying service to all other mirror node API consumers.

### Finding Description

**Code path:**

`HooksController.java` lines 80–102 and 104–130 accept `{ownerId}` as an `EntityIdParameter` path variable. Spring calls `EntityIdParameter.valueOf(id)` (lines 10–26 of `EntityIdParameter.java`) which tries three parsers in order:

1. `EntityIdNumParameter.valueOfNullable()` — numeric format, e.g. `0.0.1234`
2. `EntityIdEvmAddressParameter.valueOfNullable()` — 40-hex-char string, e.g. `0x000000000000000000000000000000000186Fb1b`
3. `EntityIdAliasParameter.valueOfNullable()` — base32 string, e.g. `HIQQEXWKW53RKN4W6XXC4Q232SYNZ3SZANVZZSUME5B5PRGXL663UAQA`

If parsing succeeds, the controller calls `hookService.getHooks(request)` → `entityService.lookup(request.getOwnerId())` (`HookServiceImpl.java` line 35).

Inside `EntityServiceImpl.lookup()` (lines 30–38):

```java
var id = switch (accountId) {
    case EntityIdNumParameter p -> Optional.of(p.id());           // NO DB query
    case EntityIdAliasParameter p ->
        entityRepository.findByAlias(p.alias()).map(EntityId::of); // DB query
    case EntityIdEvmAddressParameter p ->
        entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of); // DB query
};
return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
```

For `EntityIdAliasParameter` and `EntityIdEvmAddressParameter`, a native SQL query is issued unconditionally:

```java
// EntityRepository.java lines 13-17
@Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
Optional<Long> findByAlias(byte[] alias);

@Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**Root cause — two missing defenses:**

1. **No caching of negative results**: The `rest-java` `EntityRepository` has zero `@Cacheable` annotations (contrast with `web3`'s `EntityRepository` which caches via `CACHE_MANAGER_ENTITY`). Every request with a valid-format but non-existent address hits the database.

2. **No rate limiting in `rest-java`**: The `ThrottleConfiguration` / `ThrottleManagerImpl` / `ThrottleProperties` classes exist only in the `web3` module. There is no equivalent throttle bean, filter, or interceptor in the `rest-java` module.

**Why format validation is insufficient**: `EntityIdParameter.valueOf()` rejects truly malformed strings (e.g. `"abc"`, `"0..1"`) with `IllegalArgumentException` before any DB call. However, any syntactically valid 40-hex-char string (e.g. `0x0000000000000000000000000000000000000001` through `0xffffffffffffffffffffffffffffffffffffffff`) or any valid base32 string of 40–70 uppercase chars passes format validation and proceeds to a live DB query. There are 2^160 valid EVM addresses and an enormous alias space — an attacker has an effectively unlimited supply of valid-format, non-existent IDs.

### Impact Explanation

The `rest-java` service uses HikariCP (configured via `spring.datasource.hikari`, `CommonConfiguration.java` lines 61–95). Each concurrent request that reaches `findByAlias` or `findByEvmAddress` holds a connection from the pool for the duration of the query. With a default or small pool size, a sustained flood of concurrent requests exhausts the pool. Once exhausted, all other API requests (including legitimate ones) block waiting for a connection or fail with a connection timeout. This renders the mirror node REST API unavailable. The mirror node is a read-only query service; the Hiero consensus network itself is unaffected, but all downstream consumers relying on the mirror node API (wallets, explorers, dApps) lose access.

### Likelihood Explanation

The endpoint is unauthenticated and publicly reachable. No credentials, tokens, or special network access are required. The attack requires only the ability to send HTTP GET requests. Generating valid EVM address strings is trivial (any 40 hex characters). The attack is fully automatable, repeatable, and can be sustained indefinitely. A single attacker with modest bandwidth can maintain enough concurrent connections to saturate a small HikariCP pool.

### Recommendation

1. **Add negative-result caching** in `EntityServiceImpl` or `EntityRepository` for alias and EVM address lookups (e.g. a short-lived Caffeine cache keyed on the byte array, caching `Optional.empty()` results for a few seconds).
2. **Add rate limiting** to the `rest-java` module, mirroring the `ThrottleConfiguration` pattern from `web3`, applied at the controller or filter level, keyed per source IP.
3. **Consider rejecting alias/EVM address lookups that consistently miss** via a bloom filter or similar probabilistic structure to short-circuit DB calls for known-absent values.

### Proof of Concept

```bash
# Generate 10,000 concurrent requests with valid-format but non-existent EVM addresses
# Each triggers a live DB query; no rate limiting or negative caching stops them

for i in $(seq 1 10000); do
  # Construct a unique valid 40-hex-char EVM address
  ADDR=$(printf '%040x' $i)
  curl -s "http://<mirror-node>/api/v1/accounts/0x${ADDR}/hooks" &
done
wait

# Expected: HikariCP pool exhausted; legitimate requests begin timing out
# Observed: HTTP 503 / connection pool timeout errors for all concurrent users
```

Preconditions: Network access to the mirror node REST API (no authentication required).
Trigger: Concurrent GET requests with valid-format, non-existent EVM address or alias `ownerId` values.
Result: HikariCP connection pool exhausted; mirror node API unavailable for all users. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L30-38)
```java
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/EntityRepository.java (L13-17)
```java
    @Query(value = "select id from entity where alias = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByAlias(byte[] alias);

    @Query(value = "select id from entity where evm_address = ?1 and deleted <> true", nativeQuery = true)
    Optional<Long> findByEvmAddress(byte[] evmAddress);
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdParameter.java (L10-26)
```java
    static EntityIdParameter valueOf(String id) {
        if (StringUtils.isBlank(id)) {
            throw new IllegalArgumentException("Missing or empty ID");
        }

        EntityIdParameter entityId;

        if ((entityId = EntityIdNumParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else if ((entityId = EntityIdEvmAddressParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else if ((entityId = EntityIdAliasParameter.valueOfNullable(id)) != null) {
            return entityId;
        } else {
            throw new IllegalArgumentException("Unsupported ID format");
        }
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/HookServiceImpl.java (L35-35)
```java
        final var id = entityService.lookup(request.getOwnerId());
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/controller/HooksController.java (L80-102)
```java
    @GetMapping
    ResponseEntity<HooksResponse> getHooks(
            @PathVariable EntityIdParameter ownerId,
            @RequestParam(defaultValue = "", name = HOOK_ID, required = false)
                    @Size(max = MAX_REPEATED_QUERY_PARAMETERS)
                    NumberRangeParameter[] hookId,
            @RequestParam(defaultValue = DEFAULT_LIMIT) @Positive @Max(MAX_LIMIT) int limit,
            @RequestParam(defaultValue = "desc") Sort.Direction order) {

        final var hooksRequest = hooksRequest(ownerId, hookId, limit, order);
        final var hooksServiceResponse = hookService.getHooks(hooksRequest);
        final var hooks = hookMapper.map(hooksServiceResponse);

        final var sort = Sort.by(order, HOOK_ID);
        final var pageable = PageRequest.of(0, limit, sort);
        final var links = linkFactory.create(hooks, pageable, HOOK_EXTRACTOR);

        final var response = new HooksResponse();
        response.setHooks(hooks);
        response.setLinks(links);

        return ResponseEntity.ok(response);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-95)
```java
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
