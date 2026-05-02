### Title
No Application-Level Rate Limiting on GraphQL Endpoint Allows Max-Complexity Query Flooding

### Summary
The `graphQlCustomizer()` method in `GraphQlConfiguration.java` configures `MaxQueryComplexityInstrumentation(200)`, which rejects queries with complexity **strictly greater than** 200 but allows queries at exactly 200. No application-level rate limiting exists in the GraphQL module. An unprivileged attacker can repeatedly submit queries crafted to hit exactly complexity 200, triggering full execution (including database lookups) on every request, causing CPU and DB connection pressure and latency spikes for legitimate users.

### Finding Description

**Exact code location:** [1](#0-0) 

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**Root cause:** `MaxQueryComplexityInstrumentation(200)` in graphql-java rejects queries where computed complexity is **strictly greater than** 200 (`complexity > maxComplexity`). A query with complexity exactly 200 passes the check and proceeds to full execution. No application-level rate limiting exists in the GraphQL module — confirmed by the complete absence of any throttle/rate-limit bean or filter in the graphql source tree. [2](#0-1) 

**Failed assumption:** The complexity ceiling is assumed to prevent abuse, but it only prevents individual queries from being *too* complex. It does not prevent an attacker from sending the maximum-allowed complexity query at an unbounded rate.

**Schema enables deep nesting:** The `Account` type has recursive fields (`autoRenewAccount: Account`, `stakedAccount: Account`, `obtainer: Accountable`) and a depth limit of 10. [3](#0-2) 

With the default `SimpleComplexityCalculator` (1 per field), a query selecting ~21 fields across 9 nesting levels easily reaches exactly 200 total field selections.

**Execution path per request:** Each such query triggers `EntityServiceImpl.getByIdAndType()` → `EntityRepository.findById()` (a real DB query) for each resolved account node. [4](#0-3) 

**PreparsedDocumentProvider interaction:** The `CachedPreparsedDocumentProvider` caches the parsed+validated document keyed by query string. For repeated identical queries, parsing and validation are skipped — but the complexity instrumentation and full field execution still run on every request. This means the cache *reduces* server-side overhead for the attacker (no re-parsing cost) while the expensive parts (complexity analysis + DB queries) still execute every time. [5](#0-4) 

**Existing checks reviewed and shown insufficient:**

1. `MaxQueryComplexityInstrumentation(200)` — only rejects complexity > 200; queries at exactly 200 are fully executed.
2. `MaxQueryDepthInstrumentation(10)` — limits nesting depth but does not limit request rate.
3. Parser limits (`maxCharacters=10000`, `maxTokens=1000`) — prevent oversized query strings but do not prevent high-frequency submission of valid queries.
4. Jackson limits (`maxTokenCount=100`, `maxDocumentLength=11000`) — limit JSON body size, not request rate.
5. Traefik `inFlightReq: amount: 5` per IP — limits *concurrent* in-flight requests per source IP, not the *rate* of requests over time. Sequential flooding from one IP, or concurrent flooding from multiple IPs, is not blocked. [6](#0-5) 

### Impact Explanation
An attacker repeatedly sending complexity-200 queries forces the server to perform the maximum allowed computation and database work per request with no application-level throttle. This causes CPU saturation, DB connection pool exhaustion (the pool is shared), and increased response latency for all concurrent legitimate users. The `GraphQLHighCPU` alert threshold is 80% CPU for 5 minutes — sustained flooding can trigger this condition. The impact is availability degradation (griefing/DoS) with no economic damage to any user on the network, matching the stated scope. [7](#0-6) 

### Likelihood Explanation
No authentication or API key is required to reach the GraphQL endpoint (`/graphql/alpha`). The optimal query is trivially constructable by inspecting the public schema (available via introspection or the public GraphiQL UI at `/graphiql`). The attacker needs only a single HTTP client capable of sending POST requests in a loop. The Traefik `inFlightReq: 5` per IP is the only active guard, but it does not limit request rate — a single-threaded sequential loop from one IP is completely unthrottled. Distributed attacks (multiple IPs, VPN rotation) bypass even the concurrent-request limit entirely. [8](#0-7) 

### Recommendation
1. **Add application-level rate limiting to the GraphQL module.** Mirror the `bucket4j`-based throttle already present in the `web3` module. Apply a per-IP request-per-second limit (e.g., 10–50 req/s) using a `WebFilter` or `WebGraphQlInterceptor` in the graphql module. [9](#0-8) 

2. **Use a weighted complexity calculator.** Assign higher complexity to fields that resolve nested `Account` objects (e.g., `autoRenewAccount`, `stakedAccount`, `obtainer`) so that deeply nested queries are rejected before reaching the DB, rather than allowing the maximum number of DB-triggering fields.

3. **Lower the complexity ceiling or

### Title
No Application-Level Rate Limiting on GraphQL Endpoint Allows Max-Complexity Query Flooding

### Summary
The `graphQlCustomizer()` method in `GraphQlConfiguration` configures `MaxQueryComplexityInstrumentation(200)`, which rejects queries with complexity **strictly greater than** 200 but allows queries at exactly 200. No application-level rate limiting exists for the GraphQL module. An unprivileged attacker can craft a query at exactly complexity 200 and flood the endpoint repeatedly, triggering full execution (including database queries) on every request, causing CPU and DB connection pressure that degrades latency for legitimate users.

### Finding Description

**Exact code location:**
`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 42–49, function `graphQlCustomizer()`:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**Root cause and failed assumption:**
`MaxQueryComplexityInstrumentation(200)` rejects only queries where computed complexity **exceeds** 200 (i.e., `> 200`). A query with complexity exactly 200 passes the check and proceeds to full execution. The design assumes this ceiling is sufficient to bound per-request cost, but it does not account for the rate at which such ceiling-cost requests can be submitted.

**Exploit flow:**

1. The attacker inspects the schema (`account.graphqls`, `common.graphqls`) and identifies that `Account` has ~21 selectable fields, including recursive sub-objects (`autoRenewAccount: Account`, `stakedAccount: Account`, `entityId: EntityId`, `timestamp: TimestampRange`). With graphql-java's default `SimpleComplexityCalculator` (1 per field), selecting fields across nested levels accumulates complexity.

2. The attacker crafts a query selecting exactly 200 fields across nested `autoRenewAccount` levels (achievable within the depth-10 limit). This query passes `MaxQueryComplexityInstrumentation` and proceeds to execution.

3. The `PreparsedDocumentProvider` (`CachedPreparsedDocumentProvider`, line 26) caches the parsed document keyed by query string. On the **first** request, parsing and validation are performed and cached. On **subsequent** requests with the same query string, parsing/validation are skipped — but the complexity instrumentation and full execution (including the `EntityRepository` DB call via `EntityServiceImpl.getByIdAndType()`) still run on every request.

4. No application-level rate limiting exists in the GraphQL module. A grep across `graphql/**` for `rateLimit`, `throttle`, `RateLimit`, `inFlightReq` returns zero matches. The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) exists only in the `web3` module.

5. The only protection is the Traefik `inFlightReq: amount: 5` middleware (values.yaml, lines 138–142), which limits 5 **concurrent** in-flight requests **per source IP**. This does not limit request rate over time, and is trivially bypassed by using multiple source IPs (VPN, proxies, botnet).

**Why checks fail:**
- `MaxQueryComplexityInstrumentation(200)` is a ceiling, not a rate limit. It prevents single oversized queries but not high-frequency max-cost queries.
- `PreparsedDocumentProvider` caching reduces server-side parsing overhead for repeated queries, which paradoxically makes flooding more efficient (attacker's query is processed faster after the first hit).
- `inFlightReq: 5` per IP is infrastructure-level and per-IP only; it does not protect against distributed flooding.

### Impact Explanation

Each max-complexity request triggers at least one synchronous database query via `EntityRepository` (backed by HikariCP connection pool). Under sustained flooding from multiple IPs, the DB connection pool (`hikaricp_connections_max`) becomes saturated, causing legitimate requests to queue or time out. CPU usage rises due to repeated complexity analysis and query execution. The Prometheus alert `GraphQLHighCPU` fires at 80% CPU for 5 minutes, and `GraphQLHighDBConnections` fires at 75% pool utilization — both are reactive, not preventive. The impact is latency degradation and potential request rejection for legitimate users. No funds or on-chain state are affected, consistent with the "griefing, no economic damage" classification.

### Likelihood Explanation

The attack requires zero privileges — the GraphQL endpoint (`/graphql/alpha`) is publicly accessible with no authentication. The schema is introspectable, making it trivial to enumerate fields and calculate a complexity-200 query. The attacker needs only a script sending HTTP POST requests and a handful of IP addresses (or a single IP if the Traefik middleware is misconfigured or absent). The attack is repeatable indefinitely and requires no special knowledge beyond basic GraphQL familiarity.

### Recommendation

1. **Add application-level rate limiting to the GraphQL module.** Implement a `WebGraphQlInterceptor` (analogous to the existing `GraphQLInterceptor`) that enforces a per-IP or global request-per-second limit using Bucket4j (already a dependency in `web3`), mirroring the pattern in `ThrottleConfiguration` / `ThrottleManagerImpl`.

2. **Enforce a complexity-proportional cost per request.** Instead of a binary allow/reject at 200, track cumulative complexity consumed per IP per time window and throttle when the budget is exhausted.

3. **Reduce the complexity ceiling.** The current schema has only one query (`account`) with a small field set. A limit of 200 is far higher than needed for legitimate use; lowering it (e.g., to 50) reduces the maximum cost of each allowed request.

4. **Do not rely solely on infrastructure-level `inFlightReq`.** It is per-IP and concurrent-only; it does not bound request rate over time or protect against distributed sources.

### Proof of Concept

**Precondition:** GraphQL endpoint reachable at `http://<host>/graphql/alpha`. No credentials required.

**Step 1 — Craft a complexity-200 query** (each field counts as 1 with the default `SimpleComplexityCalculator`; nest `autoRenewAccount` to accumulate fields across levels within the depth-10 limit):

```graphql
{
  account(input: {entityId: {num: 1}}) {
    alias autoRenewPeriod balance createdTimestamp declineReward deleted
    expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
    pendingReward receiverSigRequired stakePeriodStart type
    entityId { shard realm num }
    timestamp { from to }
    autoRenewAccount {
      alias autoRenewPeriod balance createdTimestamp declineReward deleted
      expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
      pendingReward receiverSigRequired stakePeriodStart type
      entityId { shard realm num }
      timestamp { from to }
      autoRenewAccount {
        alias autoRenewPeriod balance createdTimestamp declineReward deleted
        expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
        pendingReward receiverSigRequired stakePeriodStart type
        entityId { shard realm num }
        timestamp { from to }
        autoRenewAccount {
          alias autoRenewPeriod balance createdTimestamp declineReward deleted
          expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
          pendingReward receiverSigRequired stakePeriodStart type
          entityId { shard realm num }
          timestamp { from to }
          autoRenewAccount {
            alias autoRenewPeriod balance createdTimestamp declineReward deleted
            expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
            pendingReward receiverSigRequired stakePeriodStart type
            entityId { shard realm num }
            timestamp { from to }
            autoRenewAccount {
              alias autoRenewPeriod balance createdTimestamp declineReward deleted
              expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
              pendingReward receiverSigRequired stakePeriodStart type
              entityId { shard realm num }
              timestamp { from to }
              autoRenewAccount {
                alias autoRenewPeriod balance createdTimestamp declineReward deleted
                expirationTimestamp id key maxAutomaticTokenAssociations memo nonce
                pendingReward receiverSigRequired stakePeriodStart type
                entityId { shard realm num }
                timestamp { from to }
              }
            }
          }
        }
      }
    }
  }
}
```

*(Adjust field selection to reach exactly 200 total field selections.)*

**Step 2 — Flood from multiple IPs:**

```bash
# From each of N IPs, run in parallel:
while true; do
  curl -s -X POST http://<host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query": "<above query>"}' &
done
```

**Expected result:** Server returns HTTP 200 with data (not rejected). Under sustained load from multiple IPs, DB connection pool saturates, response latency for legitimate users increases measurably, and Prometheus alerts (`GraphQLHighCPU`, `GraphQLHighDBConnections`) fire.

**Verification that complexity=200 is not rejected:** The response body will contain `"data"` (not `"errors": [{"message": "maximum query complexity exceeded"}]`), confirming the query passes the instrumentation check.

---

**Supporting code references:** [1](#0-0) [5](#0-4) [6](#0-5) [4](#0-3)

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L28-49)
```java
@Configuration
class GraphQlConfiguration {

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
    }
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L4-20)
```text
type Account implements Accountable & Entity & Node {
    "The unique alias associated with this account."
    alias: String

    "The account charged the auto-renewal fee."
    autoRenewAccount: Account

    "The amount of time to elapse before auto-renew occurs."
    autoRenewPeriod: Duration

    "The balance of the accountable entity. Defaults to tinybars."
    balance(unit: HbarUnit = TINYBAR): Long

    "The consensus timestamp at which the entity was created."
    createdTimestamp: Timestamp

    "Whether the entity declines receiving a staking reward."
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```

**File:** charts/hedera-mirror-graphql/values.yaml (L192-202)
```yaml
  GraphQLHighCPU:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} CPU usage reached {{ $value | humanizePercentage }}"
      summary: "Mirror GraphQL API CPU usage exceeds 80%"
    enabled: true
    expr: sum(process_cpu_usage{application="graphql"}) by (namespace, pod) / sum(system_cpu_count{application="graphql"}) by (namespace, pod) > 0.8
    for: 5m
    labels:
      application: graphql
      area: resource
      severity: critical
```

**File:** docs/graphql/README.md (L26-36)
```markdown
## Smoke Testing

The GraphiQL browser based GraphQL interface can be accessed at http://localhost:8083/graphiql when running the graphql
module. This tool can be used to explore the API and make adhoc requests.

If a command line tool is needed, curl can be used to make basic requests:

```bash
curl -X POST http://localhost:8083/graphql/alpha -H 'Content-Type: application/json' \
  -d '{"query": "{account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance }}"}'
```
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
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
