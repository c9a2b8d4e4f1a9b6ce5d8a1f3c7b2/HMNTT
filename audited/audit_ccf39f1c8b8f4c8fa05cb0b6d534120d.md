### Title
Unauthenticated GraphQL Request Storm via Missing Rate Limiting and Caching on `getByIdAndType()`

### Summary
The graphql module's `EntityServiceImpl.getByIdAndType()` issues an uncached, unthrottled `SELECT` to the database for every request. Unlike the `web3` and `grpc` modules which both apply `@Cacheable` to `findById()` and bucket4j rate limiting, the graphql module has neither. An unprivileged attacker can flood the public GraphQL endpoint with thousands of identical `account(input: { entityId: ... })` queries; during a network partition these queue against the HikariCP pool and, when the partition heals, all execute simultaneously, exhausting DB connections and causing service-wide unavailability.

### Finding Description
**Exact code path:**

`AccountController.account()` → `EntityService.getByIdAndType()` → `EntityRepository.findById()` → DB

`EntityServiceImpl` line 24–25:
```java
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
}
``` [1](#0-0) 

The graphql `EntityRepository` extends `CrudRepository<Entity, Long>` with no `@Cacheable` on the inherited `findById()`: [2](#0-1) 

Contrast with the `grpc` module, which annotates the same method with `@Cacheable`: [3](#0-2) 

And the `web3` module, which applies both `@Caching`/`@Cacheable` and a bucket4j `ThrottleManager`: [4](#0-3) 

The graphql module's `GraphQlConfiguration` applies only query-complexity (200) and query-depth (10) limits plus JSON parsing caps — **no per-IP rate limit, no global RPS throttle, no in-flight deduplication**: [5](#0-4) 

The bucket4j `ThrottleConfiguration` and `ThrottleManagerImpl` exist exclusively in the `web3` module and are never wired into the graphql module: [6](#0-5) 

**Root cause:** The graphql module was never given the same defensive layers (caching + rate limiting) that the web3 and grpc modules received. The failed assumption is that query-complexity limits alone are sufficient to protect the DB tier.

**Exploit flow:**
1. Attacker opens N concurrent HTTP connections to the public GraphQL endpoint (no auth required).
2. Each sends `query { account(input: { entityId: "0.0.1" }) { id } }` — complexity = 1, depth = 1, well within limits.
3. During a network partition between the graphql pod and PostgreSQL, HikariCP queues all N `findById` calls waiting for a connection.
4. When the partition heals, all N queries execute simultaneously against the DB.
5. DB connection pool is saturated; all other graphql and potentially shared-DB services are starved.

### Impact Explanation
Full DB connection pool exhaustion (`hikaricp_connections_active / hikaricp_connections_max > 0.75` triggers the existing `GraphQLHighDBConnections` alert but does not prevent the attack). [7](#0-6) 
All graphql queries fail with connection-timeout errors for the duration of the storm. If the graphql service shares a PostgreSQL instance with other mirror-node modules, those are also impacted.

### Likelihood Explanation
The GraphQL endpoint is publicly reachable with no authentication. The attack requires only an HTTP client capable of sending concurrent requests — no credentials, no special knowledge. The network-partition trigger can be simulated by the attacker themselves (e.g., TCP RST injection or simply overwhelming the connection pool without a partition). The attack is trivially repeatable and scriptable.

### Recommendation
1. **Add `@Cacheable`** to the graphql `EntityRepository.findById()` (mirroring the grpc module pattern) so repeated identical lookups are served from cache.
2. **Add a global RPS throttle** to the graphql module using the same bucket4j pattern already present in `web3/ThrottleConfiguration`, wired via a `WebFilter` or Spring Security filter.
3. **Set a HikariCP `connectionTimeout` and `maximumPoolSize`** cap specific to the graphql module so a storm cannot monopolise all DB connections.
4. Optionally, implement in-flight request deduplication (e.g., a `ConcurrentHashMap<Long, CompletableFuture<Optional<Entity>>>`) in `EntityServiceImpl` to collapse concurrent identical lookups into a single DB round-trip.

### Proof of Concept
```bash
# Send 2000 concurrent identical GraphQL queries
seq 1 2000 | xargs -P 2000 -I{} curl -s -X POST \
  -H "Content-Type: application/json" \
  -d '{"query":"{ account(input:{entityId:\"0.0.1\"}){id} }"}' \
  https://<graphql-host>/graphql

# Observe HikariCP metrics spike to max pool size:
# hikaricp_connections_active{application="graphql"} == hikaricp_connections_max
# Subsequent legitimate queries return 500 / connection timeout
```

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-25)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
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
