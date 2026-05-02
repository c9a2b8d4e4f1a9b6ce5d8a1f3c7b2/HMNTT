### Title
Unauthenticated GraphQL `account` Query Flood Exhausts Database Connection Pool (DoS)

### Summary
The GraphQL `account` query endpoint accepts unauthenticated requests and performs a synchronous database lookup for every request. No rate limiting exists within the `graphql` module itself, allowing any unprivileged attacker to flood the endpoint with concurrent valid-but-non-existent `entityId` lookups, exhausting the HikariCP connection pool and denying service to legitimate users.

### Finding Description
**Exact code path:**

`graphql/src/main/resources/graphql/query.graphqls` line 5 defines the unauthenticated `account(input: AccountInput!)` query. [1](#0-0) 

`AccountController.java` lines 33–44 handle the query: for an `entityId` input, it calls `entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)` with no guard before the DB call. [2](#0-1) 

`EntityServiceImpl.java` line 25 immediately delegates to `entityRepository.findById(entityId.getId())`, which issues a synchronous SQL `SELECT` against the database for every request, even when the entity does not exist. [3](#0-2) 

**Root cause — no rate limiting in the `graphql` module:**

`GraphQlConfiguration.java` configures only `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`, plus parser/JSON size limits. These controls govern the *structure* of a single query, not the *rate* of requests. [4](#0-3) 

The Caffeine cache configured via `hiero.mirror.graphql.cache.query` is a **preparsed document provider** (query parser cache), not a result cache — repeated lookups for non-existent IDs still hit the database every time. [5](#0-4) 

The `ThrottleConfiguration` / `ThrottleManagerImpl` with Bucket4j rate limiting exists exclusively in the `web3` module and is **not present** in the `graphql` module. [6](#0-5) 

The only filter registered in the `graphql` module is `LoggingFilter`, which only logs requests and applies no throttling. [7](#0-6) 

No Spring Security configuration exists in the `graphql` module (confirmed by grep: zero matches for `SecurityConfig`, `HttpSecurity`, `FilterChain` in `graphql/**`).

**Exploit flow:**
1. Attacker sends thousands of concurrent HTTP POST requests to `/graphql/alpha` with structurally valid but non-existent `entityId` values (e.g., `num: 999999999`).
2. Each request passes all structural checks (complexity ≤ 200, depth ≤ 10, token count ≤ 1000).
3. Each request acquires a HikariCP connection and executes `SELECT * FROM entity WHERE id = $1` returning no rows.
4. With Spring Boot's default HikariCP pool size of 10 connections, the pool is saturated by 10 concurrent in-flight queries.
5. All subsequent legitimate requests block waiting for a connection until `connectionTimeout` is exceeded, returning errors.

### Impact Explanation
Database connection pool exhaustion causes complete denial of service for the GraphQL API. All legitimate `account` queries fail with connection timeout errors. The attack requires no credentials, no special knowledge beyond the public schema, and no economic cost. The impact is scoped to the GraphQL service but is total within that scope.

### Likelihood Explanation
Any external user can discover the endpoint from public documentation (`/graphql/alpha`, documented in `docs/graphql/README.md`). The attack requires only a standard HTTP client capable of concurrent requests (e.g., `curl`, `ab`, `wrk`, or a simple script). The query payload is minimal (~80 bytes). The attack is trivially repeatable and requires no authentication.

### Recommendation
1. **Add application-level rate limiting** to the `graphql` module using Bucket4j (already a dependency in `web3`) — implement a `WebGraphQlInterceptor` or servlet filter analogous to `ThrottleManagerImpl` in `web3`, enforcing a per-IP or global requests-per-second limit.
2. **Add a result cache** for `account` lookups (e.g., Caffeine with short TTL) so repeated lookups for the same non-existent ID do not hit the database.
3. **Limit HTTP concurrency** at the servlet container level (e.g., Tomcat `maxThreads`) or via an ingress/load balancer rate limit, as noted in the design doc but not yet implemented for queries.
4. **Increase HikariCP pool size** as a mitigation (not a fix) to raise the bar for exhaustion.

### Proof of Concept
```bash
# Send 500 concurrent account queries for non-existent entityIds
seq 1 500 | xargs -P 500 -I{} curl -s -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\": \"{account(input: {entityId: {shard: 0, realm: 0, num: 9{}9999}}) { balance }}\"}" \
  -o /dev/null

# Simultaneously, legitimate requests will time out:
curl -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query": "{account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance }}"}'
# Expected: connection timeout / 503 error
```

### Citations

**File:** graphql/src/main/resources/graphql/query.graphqls (L4-6)
```text
type Query {
    account(input: AccountInput!): Account
}
```

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** docs/graphql/README.md (L17-17)
```markdown
| `hiero.mirror.graphql.cache.query`         | expireAfterWrite=1h,maximumSize=1000,recordStats | The Caffeine cache expression to use to configure the query parser cache.                                                                                                                     |
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
