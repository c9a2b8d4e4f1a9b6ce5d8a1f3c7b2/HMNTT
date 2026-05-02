### Title
Unauthenticated GraphQL `account()` Query Exhausts Database Connection Pool via Uncached `EntityRepository.findById()` (No Rate Limiting)

### Summary
The GraphQL `account()` endpoint accepts unauthenticated requests and, when queried with an `entityId` input, unconditionally calls `EntityRepository.findById()` against the database with no caching and no rate limiting. Unlike the `grpc` and `web3` modules which both apply `@Cacheable` to their `findById()` methods and have dedicated throttle infrastructure, the `graphql` module has neither, allowing any unprivileged attacker to flood the endpoint with non-existent entity IDs, exhaust the HikariCP connection pool, and render the GraphQL service unavailable.

### Finding Description

**Exact code path:**

`AccountController.account()` at [1](#0-0)  delegates to `EntityServiceImpl.getByIdAndType()`:

```java
return entityService
    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
    .map(accountMapper::map);
```

`EntityServiceImpl.getByIdAndType()` at [2](#0-1)  issues a direct database call:

```java
return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
```

`EntityRepository` in the graphql module at [3](#0-2)  extends `CrudRepository<Entity, Long>` with **no `@Cacheable` annotation** on `findById()`.

**Root cause — missing caching and missing rate limiting:**

The `grpc` module's `EntityRepository` applies `@Cacheable` directly on `findById()`: [4](#0-3) 

The `web3` module has a full `ThrottleConfiguration` with per-second request and gas buckets: [5](#0-4) 

The `graphql` module has **neither**. Its `GraphQlConfiguration` only enforces query complexity (max 200) and depth (max 10): [6](#0-5) 

These structural limits protect against a single malformed query but do nothing to limit the *rate* of well-formed, low-complexity queries. The `LoggingFilter` only logs: [7](#0-6) 

The `CachedPreparsedDocumentProvider` caches only the *parsed query document*, not the database result: [8](#0-7) 

**Exploit flow:**

An attacker sends thousands of concurrent POST requests to `/graphql/alpha` with structurally valid but non-existent `entityId` values (e.g., `{shard:0, realm:0, num:999999999}`). Each request passes `validateOneOf()`, passes complexity/depth checks, and reaches `entityRepository.findById()`. Because there is no caching and no rate limiting, every request acquires a HikariCP connection and executes a `SELECT * FROM entity WHERE id = ?`. With HikariCP's default pool size of 10, all connections are consumed immediately; subsequent requests queue indefinitely, causing request timeouts and service unavailability.

### Impact Explanation

The GraphQL service becomes unresponsive to all legitimate queries. If the GraphQL service and the importer share the same PostgreSQL instance (common in single-node deployments), the flood of concurrent connections also degrades database throughput for the importer, potentially slowing transaction ingestion. The impact is at minimum a full GraphQL service DoS; in shared-database deployments it can degrade the broader mirror node pipeline.

### Likelihood Explanation

No authentication is required. The attack requires only a valid GraphQL query structure, which is publicly documented in the Postman collection: [9](#0-8) 

Any attacker with network access to the endpoint can script this with standard HTTP tooling (e.g., `wrk`, `ab`, `curl` in parallel). The attack is trivially repeatable and requires no special knowledge beyond the public schema.

### Recommendation

1. **Add rate limiting to the GraphQL module** — implement a `ThrottleFilter` or Spring `HandlerInterceptor` analogous to the `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl`, enforcing a per-IP or global requests-per-second cap.
2. **Add `@Cacheable` to `EntityRepository.findById()`** in the graphql module, mirroring the pattern in the `grpc` module's `EntityRepository`.
3. **Configure HikariCP explicitly** with a `connectionTimeout` and `maximumPoolSize` appropriate for the expected load, and consider a separate read-replica pool for the GraphQL service.
4. **Add a concurrency/timeout limit** at the Spring WebMVC or Tomcat thread-pool level to bound the number of in-flight GraphQL requests.

### Proof of Concept

```bash
# Send 500 concurrent account queries with a non-existent entityId
seq 1 500 | xargs -P 500 -I{} curl -s -X POST \
  http://<mirror-node-host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ account(input: { entityId: { shard: 0, realm: 0, num: 999999999 } }) { entityId { num } } }"}'
```

**Expected result:** After the HikariCP pool (default 10 connections) is saturated, all subsequent requests time out or return 500 errors. Legitimate users querying real accounts also receive errors. The database shows hundreds of queued connections from the GraphQL service process.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L33-44)
```java
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-12)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L14-15)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/LoggingFilter.java (L27-38)
```java
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
        long start = System.currentTimeMillis();
        Exception cause = null;

        try {
            filterChain.doFilter(request, response);
        } catch (Exception t) {
            cause = t;
        } finally {
            logRequest(request, response, start, cause);
        }
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```

**File:** charts/hedera-mirror-graphql/postman.json (L39-39)
```json
                "query": "{\n  account(input: {\n    entityId: {\n    shard: {{shard}}, realm: {{realm}}, num: 12345}}) {\n    alais\n    autoRenewPeriod\n    autoRenewAccount {\n        alias\n        deleted\n        entityId {\n            shard\n            realm\n            num\n        }\n        createdTimestamp\n    }\n    \n  }\n}",
```
