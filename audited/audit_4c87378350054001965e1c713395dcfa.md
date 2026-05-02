### Title
Unauthenticated GraphQL Endpoint Allows DB Query Storm via Unique Entity ID Flooding in `getByIdAndType()`

### Summary
The GraphQL `/graphql` endpoint is publicly accessible with no authentication or rate limiting. Each request with a unique `entityId` bypasses the preparsed-document cache (which only caches query *structure*, not results) and issues a direct `SELECT` against the database via `entityRepository.findById()`. An attacker flooding the endpoint with thousands of unique entity IDs per second can saturate the database connection pool and CPU, degrading or halting the mirror node's ability to serve data and ingest new transactions.

### Finding Description

**Exact code path:**

`AccountController.account()` (line 43) calls `entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)`. [1](#0-0) 

`EntityServiceImpl.getByIdAndType()` (line 25) calls `entityRepository.findById(entityId.getId())` — a plain JPA `CrudRepository` call with **no `@Cacheable` annotation**. [2](#0-1) 

`EntityRepository` extends `CrudRepository<Entity, Long>` with no result-level caching configured anywhere. [3](#0-2) 

**Root cause — the cache only covers query documents, not results:**

`CachedPreparsedDocumentProvider` caches the *parsed and validated GraphQL document* keyed on the raw query string. When an attacker sends the same query string with different *variable values* (different entity IDs), the document cache hits every time, but a fresh DB call is still issued for every unique ID. [4](#0-3) 

**Why existing protections are insufficient:**

- `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` limit the *structure* of a single query, not the *rate* of requests. [5](#0-4) 
- JSON/parser size limits reject oversized payloads but do not throttle request frequency. [6](#0-5) 
- A grep across all GraphQL Java sources finds **zero** occurrences of rate limiting, throttling, or authentication (`RateLimiter`, `@PreAuthorize`, `security`, `auth`). The endpoint is fully open to anonymous callers.

### Impact Explanation

Every unique `entityId` (shard/realm/num triple — a 64-bit integer space) produces a distinct DB `SELECT`. With no rate limiting, an attacker can sustain thousands of DB queries per second from a single machine. This exhausts the database connection pool and saturates CPU, causing:

1. The mirror node's GraphQL service to become unresponsive.
2. The mirror node's importer/ingestion pipeline — which shares the same database — to stall, preventing new Hedera transaction records from being written and confirmed in the mirror.

The impact is a **denial-of-service against the mirror node** (not the Hedera consensus network itself, which is independent). Severity is **High** for the mirror node's availability.

### Likelihood Explanation

- **No authentication required** — any internet-accessible deployment is reachable by any anonymous user.
- **Trivial to automate** — a simple loop incrementing the `num` field of `entityId` generates an unbounded supply of unique cache-busting inputs.
- **Repeatable and cheap** — a single commodity machine with a fast network connection is sufficient; no special knowledge or credentials are needed.

### Recommendation

1. **Add per-IP (or global) rate limiting** at the HTTP layer (e.g., Spring's `HandlerInterceptor`, a servlet filter, or an API gateway) before requests reach the GraphQL engine.
2. **Add result-level caching** on `EntityServiceImpl.getByIdAndType()` (and the other lookup methods) using `@Cacheable` with a short TTL and a bounded maximum size, so repeated lookups for the same entity ID are served from memory.
3. **Require authentication** for the GraphQL endpoint, or at minimum enforce connection-level throttling at the infrastructure layer (load balancer / ingress).

### Proof of Concept

```bash
# Generate 10,000 requests with unique entity IDs (num = 1..10000)
for i in $(seq 1 10000); do
  curl -s -X POST https://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"query { account(input: { entityId: { shard: 0, realm: 0, num: $i } }) { balance } } \"}" &
done
wait
```

Each request carries the same query string (document cache hits), but a different `num` value forces a fresh `SELECT * FROM entity WHERE id = ?` for every iteration. Running this in parallel saturates the database, causing query latency to spike and the mirror node to become unresponsive to legitimate traffic.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L41-44)
```java
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L31-38)
```java
    static {
        // Configure GraphQL parsing limits to reject malicious input
        Consumer<Builder> consumer =
                b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
        ParserOptions.setDefaultParserOptions(
                ParserOptions.getDefaultParserOptions().transform(consumer));
        ParserOptions.setDefaultOperationParserOptions(
                ParserOptions.getDefaultOperationParserOptions().transform(consumer));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```
