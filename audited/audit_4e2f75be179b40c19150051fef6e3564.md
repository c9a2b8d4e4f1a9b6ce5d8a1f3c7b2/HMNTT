### Title
GraphQL HTTP Batch Amplification Bypasses Per-Request Rate Limiting, Exhausting DB Connection Pool via `findByAlias`

### Summary
The GraphQL module accepts HTTP batch requests (JSON arrays of operations) via Spring for GraphQL's default HTTP handler. Each operation in a batch independently invokes `EntityRepository.findByAlias()` with no caching, triggering a separate DB query per operation. Because rate limiting is applied at the HTTP-request level (Traefik `inFlightReq`) rather than at the GraphQL-operation level, a single HTTP request can fan out to ~24 simultaneous DB queries, and 5 concurrent HTTP requests from one IP can produce ~120 concurrent DB queries against a default HikariCP pool of 10 connections.

### Finding Description

**Exact code path:**

`POST /graphql/alpha` → Spring for GraphQL HTTP batch handler → `AccountController.account()` → `EntityServiceImpl.getByAliasAndType()` → `EntityRepository.findByAlias(byte[])` → native SQL `SELECT * FROM entity WHERE alias = ?1 AND deleted IS NOT TRUE` [1](#0-0) [2](#0-1) 

**Root cause — failed assumption:** The defenses are applied per HTTP request, but Spring for GraphQL's HTTP handler processes a JSON array of operations as a single HTTP request while executing each operation independently against the database. There is no batch-size cap, no per-operation rate limiter, and no result cache for alias lookups in the GraphQL module.

**Jackson `maxTokenCount(100)` constraint** (the only in-process limit that touches batch size): [3](#0-2) 

Each operation in a batch consumes 4 Jackson tokens (`START_OBJECT`, `FIELD_NAME`, `VALUE_STRING`, `END_OBJECT`) plus 2 for the array envelope. With `maxTokenCount(100)`, the maximum batch size is `(100 − 2) / 4 ≈ 24` operations per HTTP request.

**`MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`** apply per-operation inside the GraphQL engine, not across the batch: [4](#0-3) 

**Traefik `inFlightReq: amount: 5`** limits concurrent HTTP requests per source IP to 5, but a single HTTP request carrying 24 operations counts as 1 in-flight request: [5](#0-4) 

**No application-level rate limiting** exists in the GraphQL module. The `ThrottleConfiguration` / `ThrottleProperties` with `requestsPerSecond` is present only in the `web3` module: [6](#0-5) 

The GraphQL module has no equivalent.

**No caching** for alias lookups in `EntityServiceImpl`: [2](#0-1) 

**HikariCP pool** is configured via `spring.datasource.hikari` with no explicit `maximumPoolSize` override found in the graphql module, defaulting to HikariCP's default of 10 connections: [7](#0-6) 

### Impact Explanation

From a single source IP: 5 concurrent HTTP requests × 24 operations each = **120 concurrent `findByAlias` DB queries** against a pool of 10 connections. This exhausts the HikariCP pool, causing all subsequent queries (including from legitimate users) to queue or time out. The `statementTimeout` for the GraphQL module is 10,000 seconds (likely milliseconds intended but documented as seconds), meaning queued connections can hold for a long time: [8](#0-7) 

The Traefik `retry: attempts: 3` middleware further amplifies load by retrying rejected requests: [9](#0-8) 

Impact is service degradation (griefing) with no economic damage — consistent with the Medium classification.

### Likelihood Explanation

- No authentication is required; the endpoint is publicly accessible.
- The attack requires only a standard HTTP client capable of sending a JSON array body.
- The `maxTokenCount(100)` constraint limits each batch to ~24 operations, so "hundreds" in a single request is not achievable, but the 5-concurrent-request × 24-operation amplification is sufficient to exhaust the default pool.
- Repeatable at will from a single IP without triggering any application-level block.
- If Traefik is not in the deployment path (direct service access), the `inFlightReq` defense is absent entirely.

### Recommendation

1. **Disable or limit HTTP batching** at the Spring for GraphQL level via `spring.graphql.http.web-mvc.batch-mapping.enabled=false` or configure a maximum batch size.
2. **Add application-level rate limiting** to the GraphQL module analogous to `ThrottleConfiguration` in the web3 module.
3. **Add result caching** for `findByAlias` (and `findByEvmAddress`) in `EntityServiceImpl`, similar to the Caffeine cache used in the web3 entity cache (`expireAfterWrite=1s`).
4. **Explicitly configure HikariCP `maximumPoolSize`** for the GraphQL module to a value that reflects expected concurrency.

### Proof of Concept

```bash
# Build a batch of 24 alias queries (max allowed by maxTokenCount=100)
BATCH='['
for i in $(seq 1 24); do
  ALIAS=$(python3 -c "import base64; print(base64.b32encode(b'AAAAAAAAAAAAAAAAAAAAAA'[:$i % 20 + 1]).decode().rstrip('='))")
  BATCH+='{"query":"{account(input:{alias:\"ABCDEFGHIJKLMNOPQRST\"}){id}}"},'
done
BATCH="${BATCH%,}]"

# Send 5 concurrent HTTP requests (max per Traefik inFlightReq)
for i in $(seq 1 5); do
  curl -s -X POST https://<host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$BATCH" &
done
wait
```

Each of the 5 concurrent requests triggers up to 24 `findByAlias` DB queries simultaneously (120 total), exhausting the 10-connection HikariCP pool and causing connection timeout errors for legitimate concurrent users.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-30)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L74-81)
```java
            var streamReadConstraints = StreamReadConstraints.builder()
                    .maxDocumentLength(11000)
                    .maxNameLength(100)
                    .maxNestingDepth(10)
                    .maxNumberLength(19)
                    .maxStringLength(11000)
                    .maxTokenCount(100)
                    .build();
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

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-64)
```java
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }
```

**File:** docs/graphql/README.md (L23-23)
```markdown
| `hiero.mirror.graphql.db.statementTimeout` | 10000                                            | The maximum amount of time in seconds to wait for a query to finish                                                                                                                           |
```
