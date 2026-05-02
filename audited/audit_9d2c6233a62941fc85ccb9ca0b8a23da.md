### Title
Unbounded Concurrent Request Execution Exhausts Database Connection Pool in GraphQL API (Application-Layer DoS)

### Summary
The `graphQlCustomizer()` method in `GraphQlConfiguration.java` configures `MaxQueryComplexityInstrumentation(200)` as the sole execution guard, which only rejects individual queries exceeding 200 complexity units. There is no rate limiting, no per-IP throttling, and no concurrency control on the GraphQL endpoint. An unauthenticated attacker can flood the server with concurrent requests each carrying complexity 199, causing all of them to pass the complexity check and execute simultaneously against the database, exhausting the HikariCP connection pool and denying service to legitimate users.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, `graphQlCustomizer()`, lines 42–49:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

`MaxQueryComplexityInstrumentation` is a **per-request static analysis check** — it aborts a single query whose computed complexity exceeds 200. It runs before execution and has no awareness of how many other queries are currently executing. There is no global concurrency semaphore, no token-bucket rate limiter, and no per-IP throttle anywhere in the GraphQL module.

**Root cause:** The developers conflated "per-query cost bounding" with "aggregate load control." The complexity limit prevents a single catastrophically expensive query but does nothing to prevent N simultaneous near-maximum-cost queries.

**Connection pool:** The GraphQL module uses Spring's `CommonConfiguration` HikariCP data source configured via `spring.datasource.hikari` properties. HikariCP's default `maximumPoolSize` is 10. The GraphQL README documents `hiero.mirror.graphql.db.statementTimeout = 10000` ms (10 s), meaning each query can hold a connection for up to 10 seconds.

**Contrast with web3:** The web3 module has an explicit `ThrottleConfiguration` with `requestsPerSecond = 500` enforced via bucket4j. The GraphQL module has no equivalent.

**Exploit flow:**
1. Attacker crafts a valid GraphQL query with complexity 199 (e.g., a deeply nested account query with many fields, staying within the depth-10 and complexity-199 bounds).
2. Attacker sends N ≥ 10 such requests concurrently (trivially done with `curl --parallel` or any HTTP client).
3. All N requests pass `MaxQueryComplexityInstrumentation` (199 < 200) and `MaxQueryDepthInstrumentation`.
4. All N requests proceed to execution and each acquires a HikariCP connection.
5. With pool size = 10 and statement timeout = 10 s, the pool is saturated for up to 10 seconds per wave.
6. Subsequent legitimate requests block waiting for a connection; after HikariCP's `connectionTimeout` (default 30 s) they throw `SQLTimeoutException`, returning 500 errors to users.
7. Attacker repeats continuously to maintain saturation.

### Impact Explanation
All users of the GraphQL API receive errors or extreme latency for the duration of the attack. Because the GraphQL service shares the same PostgreSQL user (`mirror_graphql`) and connection pool, the impact is scoped to the GraphQL service but is complete within that scope — no legitimate query can execute while the pool is saturated. This is a non-network-based DoS: the attacker does not need to saturate bandwidth; a modest number of concurrent HTTP connections (10–20) is sufficient.

### Likelihood Explanation
No authentication is required to reach the GraphQL endpoint (`/graphql/alpha`). The attacker needs only:
- Knowledge of the public endpoint URL (documented in `docs/graphql/README.md`).
- A valid GraphQL query with complexity < 200 (trivially constructed by inspecting the public schema).
- An HTTP client capable of concurrent requests (curl, Python requests, wrk, etc.).

The attack is repeatable, requires no special privileges, and can be sustained indefinitely with minimal resources on the attacker's side.

### Recommendation
1. **Add a global rate limiter to the GraphQL module** mirroring the web3 `ThrottleConfiguration` — a bucket4j token bucket on requests per second per IP or globally.
2. **Add a concurrency limit** using a `Semaphore` or Spring WebMVC's `ConcurrentSessionFilter` equivalent to cap simultaneous in-flight GraphQL executions (e.g., max 2× pool size).
3. **Explicitly configure HikariCP pool size** for the GraphQL module and document it, rather than relying on the default of 10.
4. **Consider a `WebGraphQlInterceptor`** that rejects requests when the active connection count exceeds a threshold (readable via `HikariPoolMXBean.getActiveConnections()`).

### Proof of Concept
```bash
# Craft a complexity-199 query (adjust fields to reach target complexity)
QUERY='{"query":"{account(input:{entityId:{shard:0,realm:0,num:2}}){balance memo key type timestamp{from to} stakedAccount{balance memo key type timestamp{from to} stakedAccount{balance memo}}}}"}'

# Send 20 concurrent requests
for i in $(seq 1 20); do
  curl -s -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$QUERY" &
done
wait

# Observe: legitimate requests now return 500 / connection timeout errors
curl -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{account(input:{entityId:{shard:0,realm:0,num:2}}){balance}}"}'
```

Expected result: the final legitimate request fails or times out while the pool is saturated by the concurrent attacker requests. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-49)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
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

**File:** docs/graphql/README.md (L23-24)
```markdown
| `hiero.mirror.graphql.db.statementTimeout` | 10000                                            | The maximum amount of time in seconds to wait for a query to finish                                                                                                                           |
| `hiero.mirror.graphql.db.username`         | mirror_graphql                                   | The username used to connect to the database.                                                                                                                                                 |
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-64)
```java
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }
```
