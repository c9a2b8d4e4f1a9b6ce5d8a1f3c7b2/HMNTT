### Title
GraphQL Alias-Based Query Amplification in `account()` Resolver

### Summary
The `account()` resolver in `AccountController.java` performs a database query on every invocation. Because `MaxQueryComplexityInstrumentation` assigns a default complexity of 1 per field, an attacker can use GraphQL aliases to invoke `account` up to ~100 times in a single HTTP request while staying within the complexity limit of 200. Each aliased invocation triggers an independent database query, enabling unauthenticated amplification of backend load.

### Finding Description

**Code locations:**
- `graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java`, lines 33–58 — `account()` resolver, no caching, calls `entityService` (→ `EntityRepository`) on every invocation.
- `graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java`, line 43 — `MaxQueryComplexityInstrumentation(200)` with no custom field complexity calculator.

**Root cause:**
`MaxQueryComplexityInstrumentation` uses graphql-java's default complexity calculator, which assigns a weight of **1 per field selection**. A single `a1: account(input: {...}) { balance }` selection costs 2 complexity points (`account` = 1, `balance` = 1). With a limit of 200, an attacker can include **up to 100 aliased `account` selections** in one query document before the limit is hit.

The `CachedPreparsedDocumentProvider` caches parsed/validated documents by query string, but it does **not** deduplicate resolver executions within a single query — each aliased field is still resolved independently.

The `maxTokens(1000)` parser limit is the tighter constraint. Each alias like `a1: account(input: {entityId: {num: 1}}) { balance }` consumes approximately 19 tokens. Accounting for query wrapper overhead, ~50 aliases fit within 1000 tokens, all within the 200 complexity budget (50 × 2 = 100 < 200).

**Exploit flow:**
1. Attacker crafts a single GraphQL POST with 50 aliased `account` fields.
2. Parser accepts it (≤1000 tokens).
3. Complexity check passes (50 × 2 = 100 ≤ 200).
4. Depth check passes (depth = 2 ≤ 10).
5. graphql-java resolves each alias independently → 50 separate `EntityRepository` database queries execute. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
Each aliased `account` call hits the database with no result caching at the resolver level. An attacker sending ~50-alias queries in a tight loop can multiply their effective database query rate by 50× per HTTP request. This can exhaust database connection pools or degrade response times for legitimate users, constituting a denial-of-service amplification vector requiring zero authentication.

### Likelihood Explanation
The attack requires no credentials, no special knowledge beyond the public GraphQL schema, and is trivially scriptable. The GraphQL alias feature is standard and well-documented. Any external user who can reach the `/graphql` endpoint can exploit this immediately.

### Recommendation
1. **Assign a higher per-field complexity** to the `account` root field using a custom `FieldComplexityCalculator`. For example, assign `account` a base cost of 100 so that even 2 aliases exceed the 200 limit.
2. **Limit aliases per operation** using a custom `Instrumentation` or `ValidationRule` that counts the number of times the same root field (by field name, not alias) appears in a single operation and rejects queries exceeding a threshold (e.g., 1 or 2).
3. **Add result caching** at the service layer (e.g., a short-lived cache keyed on the lookup parameters) so repeated identical lookups within a request window do not each hit the database.

### Proof of Concept

Send the following HTTP POST to `/graphql` with no authentication:

```graphql
query {
  a01: account(input: {entityId: {num: 1}}) { balance }
  a02: account(input: {entityId: {num: 2}}) { balance }
  a03: account(input: {entityId: {num: 3}}) { balance }
  a04: account(input: {entityId: {num: 4}}) { balance }
  a05: account(input: {entityId: {num: 5}}) { balance }
  a06: account(input: {entityId: {num: 6}}) { balance }
  a07: account(input: {entityId: {num: 7}}) { balance }
  a08: account(input: {entityId: {num: 8}}) { balance }
  a09: account(input: {entityId: {num: 9}}) { balance }
  a10: account(input: {entityId: {num: 10}}) { balance }
  # ... repeat to ~50 aliases
}
```

**Expected result:** The query passes all validation gates (complexity ≈ 100, depth = 2, tokens < 1000) and triggers ~50 independent `SELECT` queries against the database in a single HTTP round-trip. Repeating this request in a loop amplifies database load by 50× compared to a single-field query.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L42-48)
```java
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L33-58)
```java
    Optional<Account> account(@Argument @Valid AccountInput input) {
        final var alias = input.getAlias();
        final var evmAddress = input.getEvmAddress();
        final var entityId = input.getEntityId();
        final var id = input.getId();

        validateOneOf(alias, entityId, evmAddress, id);

        if (entityId != null) {
            return entityService
                    .getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
        }

        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }

        throw new IllegalStateException("Not implemented");
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-41)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }

    @Override
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }

    @Override
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```
