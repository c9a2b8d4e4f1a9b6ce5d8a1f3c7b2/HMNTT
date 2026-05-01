### Title
Unauthenticated GraphQL Variable-Driven DB Query Amplification via Alias Lookup Bypass of Document Cache

### Summary
The `CachedPreparsedDocumentProvider` caches parsed GraphQL documents keyed only on the raw query string, not on variable values. An unprivileged attacker can send a constant query string with a different `alias` variable on every request, causing the document cache to be hit (avoiding parse/validate overhead) while `entityRepository.findByAlias()` executes a fresh database query on every single request. No rate limiting, authentication, or result caching exists anywhere in the GraphQL module to prevent this.

### Finding Description

**Code path:**

`CachedPreparsedDocumentProvider.getDocumentAsync()` caches by `executionInput.getQuery()` — the raw query string only: [1](#0-0) 

Variables are never part of the cache key. After the first request, every subsequent request with the same query string but a different `$alias` value skips parsing/validation entirely and proceeds directly to execution.

Execution reaches `EntityServiceImpl.getByAliasAndType()`: [2](#0-1) 

Which calls `decodeBase32(alias)` and passes the resulting `byte[]` directly to: [3](#0-2) 

This is a raw native SQL query with no result caching (`@Cacheable` or otherwise) at any layer. Every unique alias value produces a unique `byte[]` argument, guaranteeing a fresh DB round-trip on every request.

**Root cause:** The document cache and the execution pipeline are entirely decoupled. The cache eliminates parse/validate CPU cost per request, making the attack *cheaper* for the attacker while the DB cost remains constant per request. There is no result cache, no rate limiter, and no authentication anywhere in the graphql module config: [4](#0-3) 

**Existing checks and why they fail:**

- `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`: limit structural complexity of a single query, not request rate.
- `@Pattern(regexp: "^[A-Z2-7]+$")` on `alias`: validates Base32 character set only; an attacker has an enormous space of valid values (e.g., `AAAAAAAAAAAAAAAA`, `AAAAAAAAAAAAAAAB`, …).
- Parser limits (`maxCharacters=10000`, `maxTokens=1000`): prevent oversized single queries, not high-frequency small ones.
- Jackson JSON limits (`maxTokenCount=100`, `maxStringLength=11000`): prevent large payloads, not repeated small ones.
- No `SecurityConfig`, no `@PreAuthorize`, no rate-limit filter exists anywhere under `graphql/src/main/java/`. [5](#0-4) 

### Impact Explanation
An attacker with no credentials can sustain an arbitrary rate of `SELECT * FROM entity WHERE alias = ? AND deleted IS NOT TRUE` queries against the database. Because the document cache absorbs all parse/validate overhead after the first request, the attacker's per-request cost is minimal (one HTTP POST with a small JSON body), while the database absorbs one indexed lookup per request. At sufficient request rate (easily achievable from a single machine or small botnet), this can push DB CPU/IO above the 30% baseline threshold, degrading service for all legitimate users. The attack is entirely invisible to query-complexity monitoring since every individual query is structurally trivial.

### Likelihood Explanation
No privileges, API keys, or special knowledge are required. The GraphQL endpoint (`/graphql/alpha`) is publicly reachable. The attack requires only knowledge of the GraphQL schema (publicly discoverable via introspection) and a script to loop HTTP POST requests with incrementing Base32 alias values. Any attacker capable of writing a `curl` loop or using a load-testing tool (e.g., `k6`, `wrk`) can execute this. It is fully repeatable and requires no state.

### Recommendation
1. **Add a result cache** in `EntityServiceImpl.getByAliasAndType()` using Caffeine or Spring `@Cacheable` with a short TTL (e.g., 5–30 seconds), so repeated lookups for the same alias do not hit the DB.
2. **Implement per-IP or per-connection rate limiting** at the HTTP filter layer (e.g., a `OncePerRequestFilter` using a token-bucket or sliding-window counter) before requests reach the GraphQL execution engine.
3. **Consider disabling GraphQL introspection** in production to slow schema discovery.
4. **Add a global request-rate circuit breaker** (e.g., via a reverse proxy such as nginx or an API gateway) as a defense-in-depth layer independent of application code.

### Proof of Concept

```bash
# Step 1: Confirm the endpoint accepts unauthenticated alias queries
curl -s -X POST https://<host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"query Q($a:String!){account(input:{alias:$a}){entityId{num}}}","variables":{"a":"AAAAAAAAAAAAAAAA"}}'

# Step 2: Flood with unique alias values — query string is constant (document cached after first hit),
# but each alias value is unique, forcing a fresh DB query every time.
python3 - <<'EOF'
import requests, itertools, string, threading

URL = "https://<host>/graphql/alpha"
QUERY = "query Q($a:String!){account(input:{alias:$a}){entityId{num}}}"
CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"

def gen_aliases():
    for length in range(16, 20):
        for combo in itertools.product(CHARS, repeat=length):
            yield "".join(combo)

def worker(aliases):
    s = requests.Session()
    for alias in aliases:
        s.post(URL, json={"query": QUERY, "variables": {"a": alias}})

# Launch N concurrent threads
aliases = gen_aliases()
threads = [threading.Thread(target=worker, args=(aliases,)) for _ in range(50)]
for t in threads: t.start()
for t in threads: t.join()
EOF
```

Each iteration sends an identical query string (document cache hit, zero parse cost) with a unique `alias` variable, driving one `SELECT * FROM entity WHERE alias = ? AND deleted IS NOT TRUE` per request into the database with no application-layer throttle or result cache to absorb the load.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L31-39)
```java
    static {
        // Configure GraphQL parsing limits to reject malicious input
        Consumer<Builder> consumer =
                b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
        ParserOptions.setDefaultParserOptions(
                ParserOptions.getDefaultParserOptions().transform(consumer));
        ParserOptions.setDefaultOperationParserOptions(
                ParserOptions.getDefaultOperationParserOptions().transform(consumer));
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-49)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
    }
```
