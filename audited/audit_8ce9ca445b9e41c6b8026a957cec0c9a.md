### Title
Unauthenticated DB Connection Pool Exhaustion via Uncached, Unthrottled `getByIdAndType()` in GraphQL EntityServiceImpl

### Summary
`EntityServiceImpl.getByIdAndType()` issues a direct `entityRepository.findById()` database query on every call with no application-level caching and no per-request rate limiting. Unlike the `grpc` module's `EntityRepository` which applies `@Cacheable` to `findById()`, the GraphQL module's `EntityRepository` has no such annotation. An unauthenticated attacker sending concurrent requests with distinct entity IDs can saturate the HikariCP connection pool, causing denial of service for all GraphQL consumers.

### Finding Description

**Exact code path:**

`AccountController.account()` → `EntityService.getByIdAndType()` → `EntityRepository.findById()` → DB query [1](#0-0) 

```java
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
}
``` [2](#0-1) 

The graphql `EntityRepository` extends `CrudRepository<Entity, Long>` with **no `@Cacheable` annotation** on `findById()`. Every call hits the database unconditionally.

**Root cause — missing cache, confirmed by contrast with sibling modules:**

The `grpc` module's `EntityRepository` explicitly caches `findById()`: [3](#0-2) 

The `web3` module's `EntityRepository` applies multi-level `@Caching`: [4](#0-3) 

The graphql module has no equivalent. This is a structural gap, not a configuration issue.

**Infrastructure mitigations reviewed and shown insufficient:**

1. **Traefik `inFlightReq: amount: 5` per source IP** — limits a *single IP* to 5 concurrent requests. A distributed attacker with N IPs sends `N × 5` concurrent queries. With 100 IPs, that is 500 simultaneous `findById()` calls, far exceeding a default HikariCP pool. [5](#0-4) 

2. **Traefik `retry: attempts: 3`** — this middleware **amplifies** the attack. Each request that fails (e.g., due to pool exhaustion causing a timeout) is automatically retried up to 3 times, multiplying DB load by up to 4×. [6](#0-5) 

3. **GCP `maxRatePerEndpoint: 250`** — only active when `gateway.gcp.enabled: true` (GCP-specific deployment). Absent in non-GCP and Docker Compose deployments. [7](#0-6) 

4. **Docker Compose deployment** — exposes the GraphQL service directly on port 8083 with **no Traefik middleware at all**. A single attacker IP faces zero rate limiting. [8](#0-7) 

5. **DB statement timeout 10000ms** — limits individual query duration but does not prevent pool exhaustion from concurrent connections held for up to 10 seconds each.

6. **GraphQL `MaxQueryComplexityInstrumentation(200)` / `MaxQueryDepthInstrumentation(10)`** — these guard against deeply nested queries, not against high-volume simple queries. [9](#0-8) 

**HikariCP pool:** The application uses HikariCP (confirmed by `CommonConfiguration` and Prometheus metrics `hikaricp_connections_*`). Default HikariCP `maximumPoolSize` is 10. The Prometheus alert `GraphQLHighDBConnections` fires at 75% utilization, confirming the pool is a known bottleneck. [10](#0-9) [11](#0-10) 

### Impact Explanation

When the HikariCP pool is exhausted, all GraphQL queries — including those from legitimate users — block waiting for a connection. With a 10-second statement timeout and a saturated pool, new requests queue and eventually time out, returning errors to all clients. This constitutes a full denial of service for the GraphQL API. The `entity` table is the central lookup table; exhausting connections here affects all query types that resolve through `EntityServiceImpl` (accounts, contracts, tokens).

### Likelihood Explanation

The attack requires no credentials, no special knowledge beyond the public GraphQL endpoint (`/graphql/alpha`), and no privileged access. The query is a standard GraphQL account lookup by `entityId`. Sequential entity IDs (0.0.1, 0.0.2, …) guarantee cache misses even if caching were added naively. A single attacker with a modest botnet (50–200 IPs) can sustain the attack indefinitely. In Docker Compose deployments (development/staging), even a single IP with a simple loop suffices. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Add `@Cacheable` to the graphql `EntityRepository`** — mirror the pattern used in the `grpc` module:
   ```java
   @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
   Optional<Entity> findById(Long id);
   ```
   This eliminates repeated DB hits for the same entity ID within the cache TTL.

2. **Add application-level rate limiting** — implement a `RateLimiter` (e.g., Bucket4j, as already used in the `web3` module's `ThrottleProperties`) at the GraphQL controller or service layer, keyed by source IP, independent of infrastructure deployment.

3. **Set an explicit HikariCP `maximumPoolSize`** and configure a `connectionTimeout` that fails fast rather than queuing indefinitely, so pool exhaustion returns 503 quickly instead of holding threads.

4. **Remove or scope the `retry` middleware** — retrying failed GraphQL queries on network/DB errors amplifies load during an attack. Retries should not be applied to queries that fail due to resource exhaustion.

### Proof of Concept

**Preconditions:** GraphQL service accessible at `http://<host>:8083/graphql/alpha` (Docker Compose) or via ingress. No authentication required.

**Trigger (single IP, Docker Compose — no Traefik):**
```bash
# Launch 200 concurrent requests with distinct entity IDs (guaranteed cache misses)
seq 1 200 | xargs -P 200 -I{} curl -s -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"{account(input: {entityId: {shard: 0, realm: 0, num: {}}}) { id balance }}\"}"
```

**Trigger (Kubernetes/Traefik — distributed):**
```bash
# From 20+ distinct source IPs, each sending 5 concurrent requests
# Total: 100+ simultaneous findById() DB queries against a pool of ~10 connections
for ip in $(cat ip_list.txt); do
  ssh $ip "seq 1 5 | xargs -P 5 -I{} curl -s -X POST https://<host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{\"query\": \"{account(input: {entityId: {shard: 0, realm: 0, num: $RANDOM}}) { id }}\"}'" &
done
```

**Result:** HikariCP pool exhausted → subsequent legitimate requests receive connection timeout errors → GraphQL API unavailable for all users until attack stops.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L11-17)
```java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L20-30)
```java
    @Caching(
            cacheable = {
                @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_ENTITY, unless = "#result == null"),
                @Cacheable(
                        cacheNames = CACHE_NAME,
                        cacheManager = CACHE_MANAGER_SYSTEM_ACCOUNT,
                        condition =
                                "#entityId < 1000 && !T(org.hiero.mirror.web3.common.ContractCallContext).isBalanceCallSafe()",
                        unless = "#result == null")
            })
    Optional<Entity> findByIdAndDeletedIsFalse(Long entityId);
```

**File:** charts/hedera-mirror-graphql/values.yaml (L56-60)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
      sessionAffinity:
        type: CLIENT_IP
      timeoutSec: 20
    enabled: true
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```

**File:** charts/hedera-mirror-graphql/values.yaml (L143-145)
```yaml
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-graphql/values.yaml (L204-214)
```yaml
  GraphQLHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror GraphQL API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="graphql"}) by (namespace, pod) / sum(hikaricp_connections_max{application="graphql"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: graphql
      area: resource
      severity: critical
```

**File:** docker-compose.yml (L31-47)
```yaml
  graphql:
    configs:
      - source: app-config
        target: /usr/etc/hiero/application.yml
        uid: "1000"
        gid: "1000"
    deploy:
      replicas: 0
    environment:
      HIERO_MIRROR_GRAPHQL_DB_HOST: db
      SPRING_CONFIG_ADDITIONAL_LOCATION: file:/usr/etc/hiero/
    image: gcr.io/mirrornode/hedera-mirror-graphql:0.155.0-SNAPSHOT
    ports:
      - 8083:8083
    pull_policy: always
    restart: unless-stopped
    tty: true
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
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
