### Title
Cache Key Raw-String Bypass via Whitespace Variation Enables Unbounded Parse-and-Validate CPU Exhaustion

### Summary
`CachedPreparsedDocumentProvider` uses the raw query string (`executionInput.getQuery()`) as the Caffeine cache key. Because no normalization is applied before keying, semantically identical queries that differ only in whitespace (e.g., one extra space, a newline, a tab) produce distinct cache keys, each triggering a full parse-and-validate cycle. With no rate limiting present in the GraphQL module, an unauthenticated attacker can continuously flood the service with trivially varied queries, bypassing the cache entirely and exhausting CPU.

### Finding Description
**Exact code path:**

`CachedPreparsedDocumentProvider.java` line 26:
```java
return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
```
The cache key is `executionInput.getQuery()` — the verbatim query string. Two strings that are semantically identical but differ by a single whitespace character are treated as entirely different keys.

**Root cause / failed assumption:** The implementation assumes that clients will send byte-for-byte identical queries for repeated operations. In practice, any client (or attacker) can trivially vary whitespace without changing semantics.

**Exploit flow:**
1. Attacker takes any valid query, e.g. `{ account { id } }`.
2. Generates a stream of variants: `{  account { id } }`, `{   account { id } }`, `{ account  { id } }`, etc.
3. Each variant is a cache miss → `parseAndValidateFunction.apply(executionInput)` is called → full parse + validation runs.
4. The variant is stored in the 1,000-entry Caffeine cache, evicting legitimate entries.
5. Attacker repeats indefinitely; legitimate queries are also evicted and must re-parse.

**Why existing checks are insufficient:**

| Check | What it limits | What it does NOT prevent |
|---|---|---|
| `maxCharacters(10000)` | Size of a single query | Sending many small unique queries |
| `maxTokens(1000)` | Tokens per query | Sending many queries with 1–2 extra spaces |
| `maxWhitespaceTokens(1000)` | Whitespace tokens per query | Sending queries with minimal but distinct whitespace |
| `MaxQueryComplexityInstrumentation(200)` | Complexity per query | Cache bypass via whitespace |
| `MaxQueryDepthInstrumentation(10)` | Depth per query | Cache bypass via whitespace |
| Cache `maximumSize=1000` | Memory usage | CPU cost of 1,000 parse cycles before eviction; attacker keeps rotating |

No rate limiting, IP throttling, or query normalization exists anywhere in the GraphQL module.

### Impact Explanation
Every cache miss forces a full GraphQL parse-and-validate cycle. With `maxTokens(1000)` and `maxCharacters(10000)`, each cycle is bounded but non-trivial (lexing, parsing, AST construction, rule validation). An attacker sending hundreds of requests per second with unique whitespace patterns forces hundreds of full parse-and-validate cycles per second, consuming CPU proportionally. Simultaneously, the 1,000-entry cache is continuously polluted with attacker-generated entries, preventing legitimate repeated queries from ever hitting the cache and degrading service for all users. This is a non-network-based CPU DoS requiring no authentication.

### Likelihood Explanation
The attack requires zero privileges — the GraphQL endpoint is public. The technique is trivially scriptable: a single loop incrementing a space counter generates an unbounded supply of unique cache-bypassing queries. No special knowledge of the system is needed beyond knowing it exposes a GraphQL endpoint. The attack is repeatable and stateless, making it easy to sustain.

### Recommendation
Normalize the query string before using it as a cache key. The standard approach is to parse the query once to an AST and re-serialize it (canonical form), or apply a lightweight normalization (collapse all whitespace runs to a single space, strip comments) before keying. For example:

```java
// In CachedPreparsedDocumentProvider.getDocumentAsync:
String normalizedKey = normalizeQuery(executionInput.getQuery());
return cache.get(normalizedKey, key -> parseAndValidateFunction.apply(executionInput));
```

Where `normalizeQuery` collapses consecutive whitespace and strips GraphQL comments. Additionally, add per-IP or per-connection rate limiting at the HTTP layer (e.g., Spring's `HandlerInterceptor` or an API gateway) to bound the request rate regardless of query content.

### Proof of Concept
```bash
# Baseline – first request parses and caches
curl -s -X POST http://<host>/graphql \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ account { id } }"}'

# Each subsequent request adds one space, bypassing the cache
for i in $(seq 1 500); do
  SPACES=$(printf '%*s' "$i" '')
  curl -s -X POST http://<host>/graphql \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{${SPACES}account { id } }\"}" &
done
wait
```

Each iteration produces a unique raw query string → unique cache key → full parse-and-validate cycle. With 500 concurrent goroutines/threads, this saturates the parse thread pool. Monitoring the JVM (e.g., via `/actuator/metrics`) will show CPU spike and zero cache hit ratio for the query cache.