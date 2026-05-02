### Title
Connection Pool Exhaustion via Unbounded Blocking `findById()` During Database Network Partition

### Summary
`EntityServiceImpl.getByIdAndType()` calls `entityRepository.findById()` with no JDBC query timeout. During a database network partition, each call blocks indefinitely on the JDBC socket, holding a HikariCP connection-pool slot. Because no per-user rate limiting or concurrency cap exists, an unprivileged attacker can saturate the entire connection pool with as few as 10 concurrent requests, rendering the GraphQL service completely unavailable to all other users for the duration of the partition.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, line 25:
```java
return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
```
`graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` extends `CrudRepository<Entity, Long>` with no `@QueryHints(QueryHints.QUERY_TIMEOUT)` and no `@Lock` timeout. No `socketTimeout` or `queryTimeout` is configured anywhere in the graphql module (no `application.yml`/`.properties` found under `graphql/src/main/resources/`).

**Root cause:** The PostgreSQL JDBC driver's `socketTimeout` defaults to `0` (infinite) when not explicitly set. During a network partition, the OS TCP stack does not immediately signal an error; the JDBC thread blocks on `socket.read()` until the OS-level TCP keepalive fires (default: hours on Linux). Each blocked call holds one HikariCP connection slot. HikariCP's default `maximumPoolSize` is 10. Once all 10 slots are occupied by blocked threads, every subsequent request waits up to HikariCP's `connectionTimeout` (default 30 s) and then fails with `Connection is not available, request timed out`.

**Why existing checks fail:**

`GraphQlConfiguration.java` lines 43–45 install `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`. These reject structurally complex or deeply nested queries before execution, but they do not limit the *number of concurrent requests* or impose any per-user throttle. Parser limits (lines 34–38) and JSON size limits (lines 74–81) similarly address payload size, not concurrency. There is no `RateLimiter`, no servlet filter capping concurrent connections per IP, and no `@Async` / reactive boundary that would release the JDBC thread while waiting.

**Exploit flow:**
1. Attacker identifies the public GraphQL endpoint (no authentication required).
2. Attacker sends ≥10 concurrent, syntactically valid, low-complexity queries such as `{ account(input:{entityId:{shard:0,realm:0,num:1}}) { id } }`.
3. A network partition is induced (or coincides with a real outage).
4. Each query reaches `getByIdAndType()` → `findById()` → JDBC `socket.read()` → blocks indefinitely.
5. All 10 HikariCP slots are held. Legitimate requests queue and fail after 30 s.
6. Attacker re-issues requests as old ones eventually time out (OS TCP timeout), maintaining pool saturation continuously.

### Impact Explanation
Complete denial of service for all GraphQL consumers for the duration of the partition. Because the pool is shared across all users, a single attacker with 10 persistent connections starves every other user. Recovery requires either the partition to heal or an operator restart. Severity: **High** (availability impact, no authentication required, no per-user limit).

### Likelihood Explanation
The attacker needs only an HTTP client capable of 10 concurrent requests — trivially achievable with `curl`, `ab`, or any scripting language. No credentials, tokens, or special knowledge are required. Network partitions between application pods and the database are a realistic operational event (cloud AZ issues, misconfigured security groups, rolling DB maintenance). The attack is repeatable and can be scripted to re-saturate the pool automatically.

### Recommendation
1. **Set a JDBC socket timeout** on the datasource URL: `socketTimeout=30` (seconds) in the PostgreSQL JDBC URL, or via `spring.datasource.hikari.connection-timeout` and `spring.datasource.hikari.validation-timeout`.
2. **Add a JPA query hint** on `EntityRepository.findById` (or via a custom `@QueryHints` override) using `org.hibernate.timeout` / `jakarta.persistence.query.timeout`.
3. **Add per-IP or per-user rate limiting** at the servlet/gateway layer (e.g., Spring's `HandlerInterceptor` with a `RateLimiter`, or an API gateway policy) to cap concurrent GraphQL requests.
4. **Increase pool size awareness**: explicitly configure `spring.datasource.hikari.maximum-pool-size` and document the concurrency ceiling so operators can tune it.

### Proof of Concept
```bash
# Simulate 15 concurrent account queries (requires network partition to DB)
for i in $(seq 1 15); do
  curl -s -X POST http://<graphql-host>/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input:{entityId:{shard:0,realm:0,num:1}}) { id } }"}' &
done
wait

# Legitimate request now fails:
curl -X POST http://<graphql-host>/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}) { id } }"}'
# Expected: HTTP 500 or timeout — "Connection is not available, request timed out after 30000ms"
``` [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```
