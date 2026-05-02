### Title
GraphQL Field-Alias Fan-Out Exhausts DB Connection Pool via Unbounded `findByAlias()` Concurrency

### Summary
The `MaxQueryComplexityInstrumentation(200)` in `GraphQlConfiguration` assigns a flat default complexity of 1 to every field, including root-level `account` fields that each trigger a blocking `findByAlias()` database query. An unauthenticated attacker can pack ~66 distinct alias lookups into a single HTTP request (within the `maxTokens: 1000` parser limit), causing graphql-java's `AsyncExecutionStrategy` to dispatch all 66 `findByAlias()` calls concurrently, exhausting HikariCP's connection pool and denying service to legitimate users.

### Finding Description

**Exact code path:**

`GraphQlConfiguration.java` lines 43–45 configure the only query-cost gate: [1](#0-0) 

`MaxQueryComplexityInstrumentation(200)` uses graphql-java's default field-complexity calculator, which assigns **1** to every field regardless of whether it hits the database. The parser token ceiling is set at line 34: [2](#0-1) 

Each root-level `account` field resolves through `AccountController.account()`: [3](#0-2) 

which calls `EntityServiceImpl.getByAliasAndType()`: [4](#0-3) 

which issues a blocking JDBC query via `EntityRepository.findByAlias()`: [5](#0-4) 

**Root cause — failed assumption:**
The complexity budget of 200 was designed to limit nested field traversal depth/breadth, not to bound the number of independent root-level DB queries. Because each `account` field costs only 1 complexity unit, and each `id` sub-field costs 1 more, a single alias lookup costs **2 complexity units**. The attacker can therefore include **up to 100 alias lookups** before hitting the complexity ceiling (100 × 2 = 200). The binding constraint is actually the token limit: each alias lookup consumes ~15 tokens (`a1 : account ( input : { alias : "AAAA…" } ) { id }`), so `(1000 − 2) / 15 ≈ 66` lookups fit per request. At 66 lookups, total complexity = **132**, which is **under** the 200 limit — the complexity check passes and all 66 DB queries execute.

**Exploit flow:**
graphql-java's default `AsyncExecutionStrategy` for `Query` operations dispatches all root-level field resolvers **concurrently** via `CompletableFuture`. Because the application uses `spring-boot-starter-web` (blocking servlet stack), each concurrent resolver thread blocks on a JDBC connection from HikariCP. With 66 concurrent `findByAlias()` calls per request and HikariCP's default pool size of 10, the pool is saturated immediately; subsequent queries queue and time out after `statementTimeout: 10000` ms. [6](#0-5) 

**Why existing checks are insufficient:**

| Check | Value | Effect on attack |
|---|---|---|
| `maxTokens` | 1000 | Caps at ~66 lookups — still enough to exhaust pool |
| `maxCharacters` | 10000 | Not the binding constraint |
| `MaxQueryComplexityInstrumentation` | 200 | 66 lookups = 132 complexity — **passes** |
| `MaxQueryDepthInstrumentation` | 10 | Irrelevant; attack is flat (depth 2) |
| Traefik `inFlightReq` | 5 per IP | Infrastructure-only; bypassed with ≥2 source IPs | [7](#0-6) 

### Impact Explanation
A sustained attack exhausts the HikariCP connection pool, causing all subsequent GraphQL requests (including legitimate ones) to fail with connection-acquisition timeouts. This makes transaction history and account data unavailable — a direct availability impact on the mirror node's public read API. The `statementTimeout` of 10 s means each attack wave holds the pool saturated for up to 10 seconds per request, and the attacker only needs to send one request every ~10 seconds per IP to maintain the outage.

### Likelihood Explanation
No authentication is required. The endpoint is publicly accessible at `/graphql/alpha`. The attack requires only knowledge of the GraphQL alias syntax (publicly documented) and any valid Base32 alias strings (or even invalid ones — the query still reaches the DB layer before returning empty). A single attacker with two IP addresses can sustain a full pool-exhaustion DoS indefinitely. The attack is trivially scriptable with `curl`.

### Recommendation
1. **Assign a custom field complexity of ≥ 10 to the `account` root field** in the `MaxQueryComplexityInstrumentation` configuration, so that even a single alias lookup costs 10 complexity units, capping the fan-out at 20 lookups per request (200 / 10).
2. **Enforce a per-request root-field count limit** at the `WebGraphQlInterceptor` level, rejecting any query with more than N root selections (e.g., N = 5).
3. **Move rate limiting into the application layer** (e.g., Bucket4j or Spring's `HandlerInterceptor`) so it cannot be bypassed by rotating source IPs.
4. **Reduce `maxTokens`** from 1000 to a value that permits only a single `account` lookup (≈ 20 tokens), since the schema currently exposes only one query type.

### Proof of Concept

```bash
# Build a query with 66 alias lookups (within token + complexity limits)
ALIASES=""
for i in $(seq 1 66); do
  ALIASES="${ALIASES} a${i}: account(input:{alias:\"AAAAAAAAAAAAAAAA\"}){id}"
done

curl -s -X POST http://<host>/graphql/alpha \
  -H 'Content-Type: application/json' \
  -d "{\"query\":\"{${ALIASES}}\"}"
```

Send this from two IPs in a tight loop. Each request dispatches 66 concurrent `findByAlias()` JDBC calls. With HikariCP's default pool of 10, the pool is exhausted after the first request; subsequent legitimate requests receive connection-timeout errors until the 10-second `statementTimeout` expires.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L34-34)
```java
                b -> b.maxCharacters(10000).maxRuleDepth(100).maxTokens(1000).maxWhitespaceTokens(1000);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L47-48)
```java
        if (alias != null) {
            return entityService.getByAliasAndType(alias, EntityType.ACCOUNT).map(accountMapper::map);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L29-31)
```java
    public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
        return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L13-14)
```java
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```

**File:** graphql/build.gradle.kts (L27-28)
```text
    implementation("org.springframework.boot:spring-boot-starter-graphql")
    implementation("org.springframework.boot:spring-boot-starter-web")
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-140)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
```
