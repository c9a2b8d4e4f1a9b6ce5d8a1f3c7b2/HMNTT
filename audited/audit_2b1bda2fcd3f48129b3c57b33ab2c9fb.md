### Title
Fragment-Spread Complexity Undercounting in `MaxQueryComplexityInstrumentation` Enables Execution Amplification DoS

### Summary
`graphQlCustomizer()` configures `MaxQueryComplexityInstrumentation(200)` using graphql-java's `QueryTraverser`, which tracks visited fragment names in a global `Set<String>` to prevent infinite recursion. When the same named fragment is spread multiple times across different selection sets, only the first spread's fields are counted toward the complexity budget; all subsequent spreads are silently skipped. The execution engine, however, resolves the fragment's fields at every spread site, creating a measurable gap between the declared complexity budget and actual execution cost. An unprivileged external user can exploit this to force significantly more database queries per request than the budget permits.

### Finding Description

**Exact code location:**
`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, `graphQlCustomizer()`, line 43:

```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
```

**Root cause:**
graphql-java's `QueryTraverser` (used internally by `MaxQueryComplexityInstrumentation`) maintains a `visitedFragments: Set<String>` that is populated globally across the entire traversal. When a `FragmentSpread` node is encountered, the traverser checks whether the fragment name is already in the set. If it is, the traversal of that fragment's fields is skipped entirely. This is designed to prevent infinite recursion on circular fragment references, but it has the side effect that a fragment spread N times is counted as if it were spread only once.

The GraphQL execution engine has no such deduplication: it resolves the fragment's fields at every spread site in the document.

**Exploit flow:**

The `Account` type in `account.graphqls` (lines 4–81) exposes recursive object references: `autoRenewAccount: Account` (line 9) and `stakedAccount: Account` (line 67). An attacker defines a single fragment on `Account` with many scalar fields and spreads it at each level of a deeply nested account traversal:

```graphql
query {
  account(input: {entityId: {num: 1}}) {
    ...F
    autoRenewAccount {
      ...F
      autoRenewAccount {
        ...F
        autoRenewAccount {
          ...F
          autoRenewAccount { ...F }
        }
      }
    }
    stakedAccount {
      ...F
      stakedAccount {
        ...F
        stakedAccount {
          ...F
          stakedAccount { ...F }
        }
      }
    }
  }
}
fragment F on Account {
  balance memo deleted id alias nonce key type declineReward receiverSigRequired
}
```

**Complexity checker sees:**
- `account`: 1
- Fragment `F` fields (10 fields): 10 — counted **once** because `F` is added to `visitedFragments` on first encounter
- `autoRenewAccount` × 4 levels: 4
- `stakedAccount` × 4 levels: 4
- **Total: ~19** — well under the 200 limit → query is **allowed**

**Execution engine resolves:**
- 10 fields × 9 spread sites = **90 field resolutions**
- Each `autoRenewAccount` / `stakedAccount` field triggers a **separate database query** to load the referenced account
- 8 nested account-object fields = **8 DB queries** per single HTTP request

**Why existing checks fail:**

| Check | Value | Effect |
|---|---|---|
| `maxTokens` | 1000 | The above query uses ~80 GraphQL tokens — far below the limit |
| `maxCharacters` | 10000 | The query is ~400 characters — far below the limit |
| `maxDepth` | 10 | Depth is respected; the exploit works within depth 10 |
| `maxComplexity` | 200 | Bypassed due to fragment deduplication in `QueryTraverser` |
| `CachedPreparsedDocumentProvider` | cache by query string | Complexity instrumentation runs at execution time, not parse time; cache does not prevent repeated execution of the same malicious query |

The JSON-level `maxTokenCount: 100` (line 80) does not constrain this because the entire GraphQL query string is a single JSON string token.

### Impact Explanation
Each malicious request forces multiple database round-trips (one per nested `autoRenewAccount`/`stakedAccount` resolution) while appearing to consume only ~19 complexity units out of a 200-unit budget. An attacker can send ~10 such requests concurrently, each generating 8+ DB queries, exhausting the HikariCP connection pool (monitored at 75% utilization in `values.yaml` line 209). This causes cascading latency or connection-refused errors for all legitimate users. The GraphQL API is documented as publicly accessible (`/graphql/alpha`) with no authentication requirement, making this a zero-credential attack.

### Likelihood Explanation
The attack requires no authentication, no special knowledge beyond the public GraphQL schema (discoverable via introspection), and no tooling beyond `curl`. The query is compact (~400 characters), fits within all parser limits, and passes all static checks. The `CachedPreparsedDocumentProvider` actually benefits the attacker: after the first request, subsequent identical requests skip parsing overhead entirely, reducing per-request server cost for the attacker while execution cost remains constant. The attack is trivially repeatable and scriptable.

### Recommendation
Replace `MaxQueryComplexityInstrumentation` with a custom complexity calculator that counts fragment fields **per spread site**, not per fragment definition. Concretely:

1. Implement a custom `FieldComplexityCalculator` or replace `QueryTraverser` usage with a recursive visitor that does **not** deduplicate fragment names across different spread sites (only deduplicate within a single traversal path to prevent infinite recursion on circular fragments).
2. Alternatively, use a query complexity library that correctly handles fragment spread multiplication, such as `graphql-query-complexity` patterns that track spread context.
3. As an immediate mitigation, lower `MaxQueryDepthInstrumentation` to 5 and add a per-IP rate limit at the HTTP layer to reduce the blast radius.
4. Consider disabling GraphQL introspection in production to prevent schema discovery.

### Proof of Concept

```bash
curl -s -X POST http://localhost:8083/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query { account(input: {entityId: {num: 2}}) { ...F autoRenewAccount { ...F autoRenewAccount { ...F autoRenewAccount { ...F autoRenewAccount { ...F } } } } stakedAccount { ...F stakedAccount { ...F stakedAccount { ...F stakedAccount { ...F } } } } } } fragment F on Account { balance memo deleted id alias nonce key type declineReward receiverSigRequired }"
  }'
```

**Expected result:** The request is accepted (complexity ~19 < 200), but the server executes 10 fields × 9 spread sites = 90 field resolutions and issues up to 8 separate database queries for nested account objects. Sending this in a tight loop from multiple clients exhausts the DB connection pool and degrades service for all users.

**Verification:** Enable SQL query logging on the mirror node database and observe that a single GraphQL request generates multiple `SELECT` statements for account lookups corresponding to each `autoRenewAccount`/`stakedAccount` spread site. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L4-10)
```text
type Account implements Accountable & Entity & Node {
    "The unique alias associated with this account."
    alias: String

    "The account charged the auto-renewal fee."
    autoRenewAccount: Account

```

**File:** graphql/src/main/resources/graphql/account.graphqls (L65-68)
```text

    "The account to which this account is staked. Mutually exclusive with stakedNode."
    stakedAccount: Account

```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/cache/CachedPreparsedDocumentProvider.java (L24-27)
```java
    public CompletableFuture<PreparsedDocumentEntry> getDocumentAsync(
            ExecutionInput executionInput, Function<ExecutionInput, PreparsedDocumentEntry> parseAndValidateFunction) {
        return cache.get(executionInput.getQuery(), key -> parseAndValidateFunction.apply(executionInput));
    }
```
