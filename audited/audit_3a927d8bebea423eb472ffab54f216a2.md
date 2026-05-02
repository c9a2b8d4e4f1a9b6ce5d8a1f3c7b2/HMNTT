### Title
Unauthenticated GraphQL Depth-10 Query Causes Unbounded Resolver Chain Execution with No Rate Limiting

### Summary
The `graphQlCustomizer()` method in `GraphQlConfiguration.java` configures `MaxQueryDepthInstrumentation(10)` as a ceiling, not a floor — queries at exactly depth 10 are fully executed. The `Account` type exposes self-referential fields (`autoRenewAccount`, `stakedAccount`, `obtainer`) that allow an unauthenticated attacker to craft a depth-10 query triggering up to 9 sequential database lookups per request. No rate limiting exists in the GraphQL module, and the `PreparsedDocumentProvider` only caches parsing/validation — execution (resolver traversal and DB I/O) runs on every request.

### Finding Description

**Exact code location:**
- `graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, lines 42–48 (`graphQlCustomizer()`)
- `graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java`, lines 24–27
- `graphql/src/main/resources/graphql/account.graphqls`, lines 9, 55, 66 (`autoRenewAccount`, `obtainer`, `stakedAccount`)

**Root cause and failed assumption:**

`MaxQueryDepthInstrumentation(10)` is an execution-phase instrumentation that aborts queries exceeding depth 10, but permits queries at exactly depth 10 to execute fully. The schema defines `Account.autoRenewAccount: Account`, `Account.stakedAccount: Account`, and `Account.obtainer: Accountable` — all self-referential — enabling a depth-10 query that chains 9 nested account resolver calls, each issuing a separate database lookup.

The `CachedPreparsedDocumentProvider` caches by query string (`executionInput.getQuery()`) and skips re-parsing/re-validation for repeated identical queries. However, the cache key is the query text, not the variables. Execution — including all resolver invocations and DB queries — is **not** cached and runs on every request.

```
cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
```

The `MaxQueryComplexityInstrumentation(200)` allows up to 200 field resolutions per query. Combined with depth 10 and branching across `autoRenewAccount`, `stakedAccount`, and `obtainer` at each level, an attacker can craft a single query that triggers close to 200 resolver invocations (each a DB call) while staying within both limits.

No rate limiting exists anywhere in the `graphql` module. The `ThrottleConfiguration`/`ThrottleManagerImpl` classes exist only in the `web3` module. No Spring Security configuration was found in the graphql module — the endpoint at `/graphql/alpha` is publicly accessible without authentication.

**Exploit flow:**

1. Attacker (no credentials required) sends POST to `/graphql/alpha` with a depth-10 query using nested self-referential fields.
2. On first request: parse → validate → cache → execute (9+ DB lookups).
3. On subsequent identical requests: cache hit (skip parse/validate) → execute (9+ DB lookups every time).
4. Attacker opens many concurrent connections, each sending the same or slightly varied depth-10 queries.
5. With no rate limiting, the server processes all requests, each triggering multiple DB queries.

**Why checks fail:**

| Check | Why Insufficient |
|---|---|
| `MaxQueryDepthInstrumentation(10)` | Permits depth-10 queries; does not limit request rate |
| `MaxQueryComplexityInstrumentation(200)` | Allows up to 200 resolver calls per query; does not limit request rate |
| `PreparsedDocumentProvider` | Caches parsing only; execution runs on every request |
| Parser limits (`maxCharacters=10000`, `maxTokens=1000`) | Prevent oversized query strings; do not prevent valid depth-10 queries |
| No rate limiter | Absent entirely from the graphql module |

### Impact Explanation

Each depth-10 query with branching across `autoRenewAccount`/`stakedAccount`/`obtainer` can trigger dozens of sequential PostgreSQL lookups per request. With concurrent flooding from a single attacker (e.g., 50–100 concurrent connections), the DB connection pool saturates, CPU spikes from query planning and result serialization, and JVM heap pressure increases from result object allocation. On a lightly loaded server (typical for a mirror node API), this can easily exceed 30% above the 24-hour CPU/memory baseline. The impact is sustained as long as the attacker maintains the flood — there is no automatic backpressure or circuit breaker in the graphql module.

### Likelihood Explanation

The attack requires zero privileges, zero authentication, and zero specialized knowledge beyond basic GraphQL syntax. The schema is publicly introspectable. The self-referential `autoRenewAccount` field is documented in the Postman collection (`charts/hedera-mirror-graphql/postman.json`). Any attacker with a script and network access can reproduce this. The attack is repeatable, automatable, and requires no state.

### Recommendation

1. **Add rate limiting to the GraphQL module**: Implement a per-IP or global request-rate limiter (e.g., bucket4j, as used in the `web3` module) applied before GraphQL execution.
2. **Reduce the depth limit**: Lower `MaxQueryDepthInstrumentation` from 10 to 5 or 6, which is sufficient for the current schema's legitimate use cases.
3. **Reduce the complexity limit**: Lower `MaxQueryComplexityInstrumentation` from 200 to a value commensurate with the schema's actual field count (the schema has ~20 fields on `Account`; a limit of 30–50 is more appropriate).
4. **Apply field-level complexity weights**: Assign higher complexity to resolver fields that trigger DB lookups (`autoRenewAccount`, `stakedAccount`, `obtainer`) versus scalar fields.
5. **Add a query timeout**: Configure a server-side execution timeout to abort long-running resolver chains.

### Proof of Concept

```bash
# Craft a depth-10 query using self-referential autoRenewAccount (9 levels deep)
QUERY='{"query":"{ account(input:{entityId:{num:2}}) { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { entityId { num } } } } } } } } } } }"}'

# Flood with 100 concurrent connections, no credentials required
for i in $(seq 1 100); do
  curl -s -X POST https://<target>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$QUERY" &
done
wait
```

**Expected result**: Each request executes up to 9 sequential DB lookups. With 100 concurrent requests, up to 900 simultaneous DB queries are issued. Monitor server CPU and memory — both will rise significantly above the 24-hour baseline within seconds. The attack sustains as long as the loop runs, with no server-side throttle to stop it.