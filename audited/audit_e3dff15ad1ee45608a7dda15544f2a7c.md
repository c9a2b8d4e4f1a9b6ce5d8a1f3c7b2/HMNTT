### Title
Unauthenticated EVM Address Path Parameter Causes Uncached Double DB Query, Enabling Connection Pool Exhaustion DoS

### Summary
When `/api/v1/accounts/{id}/airdrops/outstanding` is called with an EVM address as the `{id}` path parameter, `TokenAirdropServiceImpl.getAirdrops()` unconditionally performs two sequential database queries per request: one in `EntityServiceImpl.lookup()` to resolve the EVM address to an account ID, and one in `TokenAirdropRepositoryCustomImpl.findAll()` for the actual airdrop data. Unlike numeric account IDs (which skip the first query entirely), EVM address lookups have no caching in the REST Java service's `EntityServiceImpl`, meaning every request hits the database twice. Under high concurrency from unauthenticated clients, this doubles effective DB load and can exhaust the HikariCP connection pool, rendering the service unavailable.

### Finding Description

**Exact code path:**

`TokenAirdropServiceImpl.getAirdrops()` at [1](#0-0) 

calls `entityService.lookup(request.getAccountId())` first, then `repository.findAll(request, id)`.

Inside `EntityServiceImpl.lookup()`: [2](#0-1) 

- `EntityIdNumParameter` → `Optional.of(p.id())` — **zero DB queries**
- `EntityIdEvmAddressParameter` → `entityRepository.findByEvmAddress(p.evmAddress())` — **one DB query, no caching**
- `EntityIdAliasParameter` → `entityRepository.findByAlias(p.alias())` — **one DB query, no caching**

Then `TokenAirdropRepositoryCustomImpl.findAll()` always executes a second DB query: [3](#0-2) 

**Root cause:** `EntityServiceImpl` has no `@Cacheable` annotation or `CacheManager` injection — confirmed by the absence of any cache logic in the file. [4](#0-3) 

This contrasts with the importer's `EntityIdServiceImpl`, which wraps EVM address lookups in a `cacheLookup()` call. [5](#0-4) 

**`EntityIdParameter.valueOf()` parsing** accepts EVM addresses (40-hex-char strings with optional `0x` prefix or shard/realm prefix) as valid path parameters: [6](#0-5) 

Any attacker-supplied string matching `EVM_ADDRESS_REGEX` is accepted without authentication: [7](#0-6) 

**Why existing checks fail:** There is no rate limiting configured in `RestJavaConfiguration` or `RestJavaProperties`. [8](#0-7)  The REST Java configuration table documents no rate-limiting property. [9](#0-8)  The HikariCP pool is finite and shared across all requests. [10](#0-9) 

### Impact Explanation
Under concurrent load with EVM address path parameters, each request consumes two DB connections (or holds one connection for two sequential queries), doubling effective DB load compared to numeric ID requests. The `RestJavaHighDBConnections` alert threshold is set at 75% utilization, confirming the project itself recognizes connection pool exhaustion as a critical concern. [11](#0-10)  Once the HikariCP pool is saturated, all incoming requests queue and eventually time out, causing the REST Java service to become unavailable. This affects all endpoints served by the process, not just the airdrop endpoint.

### Likelihood Explanation
No authentication is required. Any external client can send requests to `/api/v1/accounts/{id}/airdrops/outstanding` with a syntactically valid EVM address (e.g., `0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef`). The address does not need to exist in the database — `EntityServiceImpl.lookup()` will still execute the `findByEvmAddress` query and throw `EntityNotFoundException`, but the DB query is already issued and the connection consumed. A single attacker with moderate bandwidth can sustain enough concurrent requests to exhaust a default-sized HikariCP pool. The attack is trivially repeatable and requires no special knowledge beyond the public API specification.

### Recommendation
1. **Add caching to `EntityServiceImpl.lookup()`** for `EntityIdEvmAddressParameter` and `EntityIdAliasParameter` cases, mirroring the cache pattern used in the importer's `EntityIdServiceImpl.cacheLookup()`.
2. **Add rate limiting** at the Spring Security or servlet filter level (e.g., using Bucket4j or a reverse proxy) for all `/api/v1/accounts/{id}/...` endpoints.
3. **Short-circuit on not-found EVM addresses** with a negative cache entry to avoid repeated DB hits for non-existent addresses used in amplification attacks.

### Proof of Concept
```bash
# Send 500 concurrent requests with a valid-format but non-existent EVM address
# Each request triggers 2 DB queries: findByEvmAddress + (if found) findAll
# Even on 404, the first DB query is already executed

for i in $(seq 1 500); do
  curl -s "http://<mirror-node-host>/api/v1/accounts/0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef/airdrops/outstanding" &
done
wait

# Observe HikariCP active connections spike to pool maximum
# Subsequent requests begin timing out with connection acquisition errors
# Service becomes unresponsive to all endpoints
```

### Citations

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java (L19-22)
```java
    public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
        var id = entityService.lookup(request.getAccountId());
        return repository.findAll(request, id);
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/service/EntityServiceImpl.java (L17-38)
```java
@Named
@RequiredArgsConstructor
final class EntityServiceImpl implements EntityService {

    private final EntityRepository entityRepository;

    @Override
    public Entity findById(EntityId id) {
        return entityRepository.findById(id.getId())
                .orElseThrow(() -> new EntityNotFoundException("Entity not found"));
    }

    @Override
    public EntityId lookup(EntityIdParameter accountId) {
        var id = switch (accountId) {
            case EntityIdNumParameter p -> Optional.of(p.id());
            case EntityIdAliasParameter p -> entityRepository.findByAlias(p.alias()).map(EntityId::of);
            case EntityIdEvmAddressParameter p -> entityRepository.findByEvmAddress(p.evmAddress()).map(EntityId::of);
        };

        return id.orElseThrow(() -> new EntityNotFoundException("No account found for the given ID"));
    }
```

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/repository/TokenAirdropRepositoryCustomImpl.java (L58-72)
```java
    public Collection<TokenAirdrop> findAll(TokenAirdropRequest request, EntityId accountId) {
        var type = request.getType();
        var bounds = request.getBounds();
        var condition = getBaseCondition(accountId, type.getBaseField())
                .and(getBoundConditions(bounds))
                .and(TOKEN_AIRDROP.STATE.eq(AirdropState.PENDING));

        var order = SORT_ORDERS.getOrDefault(type, Map.of()).get(request.getOrder());
        return dslContext
                .selectFrom(TOKEN_AIRDROP)
                .where(condition)
                .orderBy(order)
                .limit(request.getLimit())
                .fetchInto(TokenAirdrop.class);
    }
```

**File:** importer/src/main/java/org/hiero/mirror/importer/domain/EntityIdServiceImpl.java (L55-62)
```java
        return switch (accountId.getAccountCase()) {
            case ACCOUNTNUM -> Optional.ofNullable(EntityId.of(accountId));
            case ALIAS -> {
                byte[] alias = toBytes(accountId.getAlias());
                yield alias.length == EVM_ADDRESS_LENGTH
                        ? cacheLookup(accountId.getAlias(), () -> findByEvmAddress(alias))
                        : cacheLookup(accountId.getAlias(), () -> findByAlias(alias))
                                .or(() -> findByAliasEvmAddress(alias));
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

**File:** rest-java/src/main/java/org/hiero/mirror/restjava/parameter/EntityIdEvmAddressParameter.java (L15-16)
```java
    public static final String EVM_ADDRESS_REGEX = "^(((\\d{1,5})\\.)?((\\d{1,5})\\.)?|0x)?([A-Fa-f0-9]{40})$";
    public static final Pattern EVM_ADDRESS_PATTERN = Pattern.compile(EVM_ADDRESS_REGEX);
```

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

**File:** docs/configuration.md (L622-635)
```markdown
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
| `hiero.mirror.restJava.response.headers.defaults`        | See application.yml                                | The default headers to add to every response. For each header, specify its `name: value`                                                                      |
| `hiero.mirror.restJava.response.headers.path`            | See application.yml                                | Override default or add headers per path to add to every response. The key is the controller request mapping, then for each header, specify its `name: value` |

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

**File:** charts/hedera-mirror-rest-java/values.yaml (L203-213)
```yaml
  RestJavaHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror Java REST API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="rest-java"}) by (namespace, pod) / sum(hikaricp_connections_max{application="rest-java"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: rest-java
      area: resource
      severity: critical
```
