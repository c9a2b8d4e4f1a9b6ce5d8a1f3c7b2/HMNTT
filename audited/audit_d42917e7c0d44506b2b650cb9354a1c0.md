### Title
Cache Thrashing DoS via Unbounded Unique Query Flooding in CachedPreparsedDocumentProvider

### Summary
The `CachedPreparsedDocumentProvider.getDocumentAsync()` method caches parsed GraphQL documents keyed solely by raw query string with a hard cap of 1000 entries and no per-IP or per-user rate limiting in the graphql module. An unauthenticated attacker can continuously submit unique valid query strings to fill and continuously evict the Caffeine cache, forcing every subsequent legitimate request to re-execute the expensive parse-and-validate path, causing sustained CPU exhaustion and service degradation.

### Finding Description

**Code location:**

- `graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java`, lines 24–27
- `graphql/src/main/java/org/hiero/mirror/graphql/cache/CacheProperties.java`, line 15
- `graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 31–39

**Root cause:**

`getDocumentAsync()` delegates directly to `cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput))` with no admission control:

```java
// CachedPreparsedDocumentProvider.java:24-27
public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
        ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
    return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
}
```

The cache is configured with `maximumSize=1000` and `expireAfterWrite=1h`:

```java
// CacheProperties.java:15
private String query = "expireAfterWrite=1h,maximumSize=1000,recordStats";
```

Caffeine evicts entries (LRU) once the 1000-entry limit is reached. There is **no rate limiting** in the graphql module — the `ThrottleConfiguration`/`ThrottleManagerImpl` exist exclusively in the `web3` module. The graphql module has only a `LoggingFilter` with no throttling logic.

**Exploit flow:**

1. Attacker sends 1000 structurally distinct but syntactically valid GraphQL queries (e.g., varying field aliases, argument values, or whitespace-padded strings — all within the `maxCharacters=10000` / `maxTokens=1000` parser limits).
2. Each unique query string is inserted into the cache, filling it to capacity.
3. Attacker continues sending new unique queries at high rate. Caffeine evicts the oldest entries to make room.
4. Legitimate cached queries are continuously evicted. Every subsequent legitimate request misses the cache and triggers `parseAndValidateFunction.apply()` — a CPU-intensive parse + schema validation cycle.
5. Under concurrent load, many threads simultaneously execute parse+validate, saturating the JVM thread pool and CPU.

**Why existing checks fail:**

- `maxCharacters(10000)`, `maxTokens(1000)`, `maxRuleDepth(100)` — these limit per-query cost but do not prevent high-volume unique-query submission.
- `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)` — these run **after** parsing, so they do not prevent the parse cost from being incurred on every cache miss.
- JSON limits (`maxTokenCount(100)`, `maxStringLength(11000)`) — constrain request body size but still allow 1000 distinct valid queries.
- No authentication, no per-IP rate limiting, no request-per-second cap exists anywhere in the graphql module.

### Impact Explanation

Every cache miss triggers a full GraphQL parse and schema validation cycle. With `maximumSize=1000` and continuous unique-query flooding, the effective cache hit rate for legitimate traffic approaches zero. Under concurrent attack traffic, the Spring servlet thread pool becomes saturated with parse+validate work. This causes:

- Severe latency increase for all GraphQL requests (legitimate and attacker)
- Thread pool exhaustion leading to request queuing and eventual rejection
- Elevated CPU usage that can starve the JVM of resources needed for DB connection management and response handling, effectively degrading or severing the application's ability to serve database-backed responses

Severity: **High** (unauthenticated, remotely exploitable, causes full service degradation)

### Likelihood Explanation

- No authentication is required; the GraphQL endpoint is publicly accessible.
- Generating 1000 unique valid GraphQL queries is trivial (e.g., `{ accounts(entityId: {eq: "0.0.N"}) { id } }` with N = 1..1000).
- The attack is repeatable and self-sustaining: once the cache is full, the attacker only needs to maintain a rate of ~1 new unique query per eviction cycle to keep cache hit rate near zero.
- Standard HTTP flood tooling (wrk, ab, curl loops) is sufficient; no special privileges or exploits needed.
- The web3 module has rate limiting; the graphql module does not — this asymmetry suggests the graphql module's rate limiting was overlooked.

### Recommendation

1. **Add per-IP rate limiting to the graphql module** — implement a `ThrottleFilter` (analogous to the web3 `ThrottleManagerImpl`) using Bucket4j, applied before GraphQL execution.
2. **Bound cache insertion rate** — reject or queue requests when the incoming unique-query rate exceeds a configurable threshold.
3. **Normalize cache keys** — strip comments and normalize whitespace before using the query string as a cache key, reducing the attacker's ability to generate trivially unique strings.
4. **Consider authenticated access** — if the GraphQL API is not intended for anonymous public use, add authentication to eliminate unauthenticated flooding entirely.

### Proof of Concept

```bash
# Generate 1001 unique valid queries and send them concurrently
for i in $(seq 1 1001); do
  curl -s -X POST http://<host>/graphql \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ accounts(entityId: {eq: \\\"0.0.$i\\\"}) { id } }\"}" &
done
wait

# Now send a legitimate repeated query and observe parse latency on every request
# (cache is thrashed; no entry survives long enough to be reused)
for i in $(seq 1 100); do
  time curl -s -X POST http://<host>/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ accounts(entityId: {eq: \"0.0.2\"}) { id } }"}'
done
```

Expected result: response latency for the repeated legitimate query does not decrease across iterations (no cache benefit), and under concurrent flood traffic, requests begin timing out or returning 5xx errors as the thread pool saturates.