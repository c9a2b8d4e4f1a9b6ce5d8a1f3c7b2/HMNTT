### Title
Thread Exhaustion via Unbounded Blocking DB Calls in `getByIdAndType()` During Network Partition

### Summary
`EntityServiceImpl.getByIdAndType()` calls `entityRepository.findById()` — a plain Spring Data JPA `CrudRepository` method — with no query timeout, no socket timeout, and no per-client rate limiting. During a database network partition, JDBC threads block indefinitely at the socket level, and because the GraphQL endpoint is unauthenticated and unconstrained by request rate, an attacker can saturate the HikariCP connection pool and degrade the Tomcat thread pool, causing a sustained denial of service.

### Finding Description

**Exact code path:**

`EntityServiceImpl.getByIdAndType()` at line 25 delegates directly to `entityRepository.findById()`:

```java
// EntityServiceImpl.java line 24-26
public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
    return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
}
```

The graphql-module `EntityRepository` extends `CrudRepository<Entity, Long>` with no custom `findById` override, no `@QueryHints(QueryHints.SPEC_HINT_TIMEOUT)`, and no `@Transactional(timeout=...)`:

```java
// EntityRepository.java line 12
public interface EntityRepository extends CrudRepository<Entity, Long> {
    // findById() is inherited — no timeout, no cache
}
```

No application-level JDBC `socketTimeout` or `queryTimeout` is configured in the graphql module (no `application.yml`/`.properties` found under `graphql/src/main/resources/`).

**Why existing checks fail:**

`GraphQlConfiguration` applies only structural query guards — complexity (200), depth (10), token/character limits — none of which limit request concurrency or DB execution time:

```java
// GraphQlConfiguration.java line 43-45
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

There is no rate limiter, no per-IP throttle, and no authentication requirement on the GraphQL endpoint. The `AccountController` is a public `@Controller` with no security annotation.

**Exploit flow:**

1. Attacker identifies the public `/graphql` endpoint.
2. During a DB network partition (or induced by saturating DB connections), the PostgreSQL JDBC driver holds open TCP sockets that never receive data and never time out (no `socketTimeout` in JDBC URL).
3. Attacker sends N concurrent GraphQL queries (e.g., `{ account(entityId: "0.0.1") { id } }`) where N equals the HikariCP pool size (default: 10).
4. Each request acquires a HikariCP connection and blocks indefinitely in `findById()`.
5. HikariCP pool is exhausted. Subsequent requests queue and wait up to `connectionTimeout` (HikariCP default: 30 s), blocking their Tomcat threads during that wait.
6. Attacker sustains a stream of requests at a rate that keeps all 200 Tomcat threads occupied (10 permanently blocked on JDBC sockets, 190 cycling through 30 s HikariCP waits).
7. The service becomes unresponsive to all users.

### Impact Explanation

The service is rendered unavailable for the duration of the partition plus attacker activity. The 10 threads holding live JDBC connections are permanently blocked (no socket-level timeout), and the remaining Tomcat threads are continuously consumed by requests waiting for a HikariCP connection slot. No privileged access is required. Any entity ID accepted by the schema (e.g., `0.0.1`) is sufficient to trigger a real DB call.

### Likelihood Explanation

The endpoint is public and unauthenticated. The attacker needs only a valid `EntityId` value (trivially guessable from the schema or public Hedera network data) and the ability to send concurrent HTTP requests. No exploit tooling beyond `curl` or `ab` (Apache Bench) is required. The attack is repeatable and automatable. A network partition can be induced externally (BGP manipulation, firewall rule injection) or the attacker can simply flood the DB with long-running queries from another vector to simulate the same effect.

### Recommendation

1. **Add a JDBC socket timeout** to the datasource URL: `socketTimeout=30` (seconds) for PostgreSQL, ensuring blocked JDBC reads surface as exceptions rather than hanging indefinitely.
2. **Add a query timeout** via `@Transactional(timeout = 5)` on `getByIdAndType()` or via Spring Data `@QueryHints`.
3. **Configure HikariCP** with an explicit `connection-timeout` and `max-lifetime` in the graphql module's datasource properties.
4. **Add request-level rate limiting** (e.g., Spring's `RateLimiter`, Bucket4j, or an API gateway) on the `/graphql` endpoint to bound concurrent requests per client.
5. **Set Tomcat's** `server.tomcat.connection-timeout` to a value shorter than the JDBC socket timeout to ensure HTTP connections are released before threads are permanently consumed.

### Proof of Concept

```bash
# Simulate DB partition (e.g., drop DB traffic via iptables on the DB host):
# iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# Then flood the GraphQL endpoint with concurrent requests:
ab -n 10000 -c 200 \
  -p query.json \
  -T 'application/json' \
  http://<graphql-host>/graphql

# query.json:
# {"query":"{ account(entityId: \"0.0.1\") { id } }"}

# Expected result: all 200 Tomcat threads consumed within seconds;
# service returns 503 or hangs for all subsequent clients.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-48)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-44)
```java
    @QueryMapping
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
```
