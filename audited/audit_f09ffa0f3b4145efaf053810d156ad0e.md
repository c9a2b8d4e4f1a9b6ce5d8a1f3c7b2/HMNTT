### Title
Unauthenticated High-Frequency Near-Maximum Complexity Queries Cause Sustained Database Load (No Rate Limiting on GraphQL Endpoint)

### Summary
The GraphQL module enforces a complexity ceiling of 200 via `MaxQueryComplexityInstrumentation(200)` but applies **no per-IP or per-request rate limiting**. An unauthenticated attacker can repeatedly submit queries with complexity exactly at 199 — the maximum allowed — each of which resolves multiple nested `Account` objects and triggers several independent database lookups per request. Because there is no throttle on the GraphQL endpoint, this can be sustained indefinitely, degrading response times for all legitimate users.

### Finding Description

**Exact code location:**
`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, `graphQlCustomizer()`, lines 42–48:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**Root cause — failed assumption:** The design assumes that a complexity ceiling of 200 is sufficient to bound server work per request. It does not account for the absence of any rate-limiting mechanism on the GraphQL endpoint itself. The `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j-based rate limiting) exists only in the `web3` module; there is no equivalent in the `graphql` module. No `SecurityFilterChain`, no `requestsPerSecond` property, and no per-IP throttle exist for the GraphQL service.

**Exploit flow:**

1. The `Account` schema type exposes fields that resolve to additional `Account` objects: `autoRenewAccount: Account`, `stakedAccount: Account`, and `obtainer: Accountable`. Each of these triggers a separate call through `AccountController` → `EntityService` → `EntityRepository` (a database query).
2. With `MaxQueryDepthInstrumentation(10)` and `MaxQueryComplexityInstrumentation(200)`, an attacker can craft a single query that nests `autoRenewAccount` and `stakedAccount` sub-selections across multiple depth levels, requesting ~19 scalar fields at each level, keeping total complexity at 199.
3. The `CachedPreparsedDocumentProvider` (Caffeine cache, `expireAfterWrite=1h`) caches the parsed AST keyed on the query string. This means parsing/validation overhead is paid only once per unique query string. **Execution (field resolution and DB queries) is NOT cached** — it runs on every request.
4. Because there is no rate limit, the attacker can send this same 199-complexity query at the maximum rate the network allows, causing a continuous stream of multi-DB-query executions.

**Why existing checks fail:**
- `MaxQueryComplexityInstrumentation(200)`: Allows 199-complexity queries; does not limit request frequency.
- `MaxQueryDepthInstrumentation(10)`: Limits nesting depth but not breadth or frequency.
- Parser limits (`maxCharacters=10000`, `maxTokens=1000`): Prevent oversized query strings but do not prevent high-frequency submission of a valid, within-limit query.
- `CachedPreparsedDocumentProvider`: Reduces parse overhead but does not reduce DB execution load.
- No `SecurityFilterChain`, no bucket4j throttle, no IP-based rate limiting in the `graphql` module.

### Impact Explanation
Each 199-complexity request with nested `Account` fields causes multiple sequential or parallel database queries against the mirror node PostgreSQL database. Under sustained high-frequency attack, the database connection pool (monitored via `hikaricp_connections_active`) can be saturated, causing legitimate queries to queue or time out. The `db.statementTimeout` for the GraphQL module is 10,000 ms, meaning each held connection can block for up to 10 seconds. This degrades response times for all legitimate users of the GraphQL API. The impact is scoped to the mirror node service (not the Hedera network itself), consistent with the "griefing" severity classification.

### Likelihood Explanation
The attack requires zero privileges — the `/graphql/alpha` endpoint is publicly accessible with no authentication. The attacker needs only a single valid account entity ID (e.g., `{shard:0, realm:0, num:2}`, a well-known system account) and a crafted query string. The query can be sent in a tight loop from a single machine or distributed across multiple IPs. The `CachedPreparsedDocumentProvider` actually aids the attacker by eliminating parse overhead after the first request, making each subsequent request cheaper for the attacker while still causing full DB execution load on the server. This is trivially repeatable and scriptable.

### Recommendation
1. **Add rate limiting to the GraphQL module**: Introduce a bucket4j-based `requestsPerSecond` throttle (analogous to `web3`'s `ThrottleConfiguration`) applied at the HTTP filter level before GraphQL execution.
2. **Add per-IP rate limiting**: Use a per-source-IP token bucket to prevent a single client from monopolizing the endpoint.
3. **Cache execution results**: For read-only queries against largely static data (account lookups), introduce a short-lived result cache (e.g., 1–5 seconds) to prevent repeated identical queries from hitting the database.
4. **Reduce the complexity ceiling**: Evaluate whether 200 is necessary given the current schema; a lower limit (e.g., 50–100) would reduce the maximum DB work per request.
5. **Require authentication or API keys** for the GraphQL endpoint to enable per-client throttling and abuse tracking.

### Proof of Concept

**Precondition:** GraphQL service running at `http://localhost:8083/graphql/alpha`, no credentials required.

**Crafted query (complexity ≈ 199, depth ≤ 10, triggers multiple DB lookups per request):**

```graphql
{
  account(input: {entityId: {shard: 0, realm: 0, num: 2}}) {
    alias autoRenewPeriod balance createdTimestamp declineReward
    deleted expirationTimestamp id key maxAutomaticTokenAssociations
    memo nonce pendingReward receiverSigRequired stakePeriodStart
    entityId { shard realm num }
    timestamp { from to }
    type
    autoRenewAccount {
      alias autoRenewPeriod balance createdTimestamp declineReward
      deleted expirationTimestamp id key memo nonce pendingReward
      receiverSigRequired stakePeriodStart type
      entityId { shard realm num }
      timestamp { from to }
      autoRenewAccount {
        alias balance memo type entityId { shard realm num }
      }
    }
    stakedAccount {
      alias balance memo type entityId { shard realm num }
      timestamp { from to }
    }
  }
}
```

**Attack loop (bash):**
```bash
QUERY='{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}){ alias autoRenewPeriod balance createdTimestamp declineReward deleted expirationTimestamp id key maxAutomaticTokenAssociations memo nonce pendingReward receiverSigRequired stakePeriodStart entityId{shard realm num} timestamp{from to} type autoRenewAccount{alias autoRenewPeriod balance createdTimestamp declineReward deleted expirationTimestamp id key memo nonce pendingReward receiverSigRequired stakePeriodStart type entityId{shard realm num} timestamp{from to} autoRenewAccount{alias balance memo type entityId{shard realm num}}} stakedAccount{alias balance memo type entityId{shard realm num} timestamp{from to}} } }"}'

while true; do
  curl -s -X POST http://localhost:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$QUERY" > /dev/null &
done
```

**Expected result:** Database connection pool utilization rises toward 100% (observable via `hikaricp_connections_active` Prometheus metric), GraphQL request latency increases beyond the 2s alert threshold (`GraphQLRequestLatency` alert fires), and legitimate users receive slow or timed-out responses.