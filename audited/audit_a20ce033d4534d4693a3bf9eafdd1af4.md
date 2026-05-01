### Title
Unauthenticated, Unbounded Request Rate on `/graphql/alpha` Enables Database-Exhaustion DoS

### Summary
The `/graphql/alpha` GraphQL endpoint exposes the `account(input: AccountInput!)` query with no per-IP or per-session rate limiting. Every request with a distinct `evmAddress` variable bypasses the query-document cache and issues a live database query, allowing any unauthenticated attacker to flood the endpoint and exhaust the database connection pool, degrading or halting the mirror node's ability to serve data.

### Finding Description
**Code path:**

- Schema entry point: `graphql/src/main/resources/graphql/query.graphqls` line 5 — `account(input: AccountInput!): Account`
- Controller: `graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java` lines 33–58 — `@QueryMapping Optional<Account> account(...)` — no authentication annotation, no rate-limit annotation.
- Service: `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java` lines 34–41 — `getByEvmAddressAndType` calls `entityRepository.findByEvmAddress(evmAddressBytes)` unconditionally.
- Repository: `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` lines 16–17 — native SQL `select * from entity where evm_address = ?1 and deleted is not true` executed per request.

**Root cause — failed assumption:**
`GraphQlConfiguration.java` lines 42–48 installs `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`. These limit the *structural cost of a single query* but impose no constraint on *how many queries per second* a single IP may submit. The `CachedPreparsedDocumentProvider` (lines 24–27) caches the parsed query document keyed by the query string; when the attacker reuses the same query string and only varies the `evmAddress` GraphQL variable, the parse step is cached but the database call is not — every request still hits the DB. No `SecurityFilterChain`, no `bucket4j`/`resilience4j` rate limiter, and no Spring Security configuration exist anywhere in the `graphql/` module.

**Exploit flow:**
1. Attacker constructs a minimal, valid query: `{ account(input: { evmAddress: "0x<addr>" }) { id } }` — complexity ≈ 1, depth = 1, well within all instrumentation limits.
2. Attacker sends this query in a tight loop, rotating `evmAddress` values (or even reusing the same one) at thousands of requests per second from one or more IPs.
3. Each request passes all structural checks, reaches `EntityServiceImpl.getByEvmAddressAndType`, and issues a `SELECT` against the `entity` table.
4. The database connection pool is saturated; legitimate queries time out or are rejected.

**Why existing checks are insufficient:**
- `MaxQueryComplexityInstrumentation(200)` — the `account` query has complexity ≈ 1; this check never fires.
- `MaxQueryDepthInstrumentation(10)` — depth = 1; never fires.
- Parser limits (`maxCharacters=10000`, `maxTokens=1000`) — a minimal `account` query is ~60 characters; never fires.
- `CachedPreparsedDocumentProvider` — caches parse results, not DB results; rotating variables defeats it entirely.
- `LoggingFilter` — logs only, no blocking.

### Impact Explanation
The mirror node's GraphQL service becomes unavailable to legitimate consumers. Database connection exhaustion can cascade to other services sharing the same DB instance (e.g., the REST API). Because the mirror node is the authoritative read path for account state, transaction history, and related data, a sustained DoS prevents clients from querying any account or transaction data. Severity: **High** (availability impact, no authentication required, no mitigating control in-code).

### Likelihood Explanation
The endpoint is publicly reachable with no credentials. The attack requires only an HTTP client and a loop — no special knowledge, no privileged access, no exploit chain. A single machine with a modest network connection can sustain thousands of requests per second. The attack is trivially repeatable and automatable.

### Recommendation
1. **Add per-IP rate limiting** at the servlet filter layer (e.g., `bucket4j-spring-boot-starter` or a custom `OncePerRequestFilter` using a `Caffeine`-backed token bucket keyed by `request.getRemoteAddr()`).
2. **Add result-level caching** in `EntityServiceImpl` (e.g., Spring `@Cacheable`) so repeated lookups for the same `evmAddress` do not hit the DB.
3. **Enforce a global request concurrency limit** via Tomcat/Undertow thread-pool configuration or a semaphore in the filter chain.
4. **Deploy an API gateway or WAF** in front of the service with rate-limiting rules as a defense-in-depth layer.

### Proof of Concept
```bash
# Requires: curl, GNU parallel or a simple loop
# Sends 5000 account queries with rotating evmAddress values, no credentials needed

for i in $(seq 1 5000); do
  ADDR=$(printf "0x%040x" $i)
  curl -s -X POST http://<mirror-node-host>/graphql/alpha \
    -H "Content-Type: application/json" \
    -d "{\"query\":\"{ account(input: { evmAddress: \\\"$ADDR\\\" }) { id } }\"}" &
done
wait
# Observe: DB connection pool exhaustion, 500 errors or timeouts for legitimate users
```

Each iteration issues a structurally valid query (complexity 1, depth 1) that bypasses all instrumentation checks and triggers a live `SELECT` on the `entity` table. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** graphql/src/main/resources/graphql/query.graphqls (L4-6)
```text
type Query {
    account(input: AccountInput!): Account
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-58)
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
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
        }

        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        throw new IllegalStateException("Not implemented");
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```
