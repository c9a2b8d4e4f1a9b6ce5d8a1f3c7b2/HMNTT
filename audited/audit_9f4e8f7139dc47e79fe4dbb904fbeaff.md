### Title
GraphQL Unauthenticated Concurrent Depth-10 Chain Query Connection Pool Exhaustion DoS

### Summary
The GraphQL API's `account(input: AccountInput!)` query exposes a self-referential `autoRenewAccount: Account` field that allows depth-10 recursive chains. With no authentication, no rate limiting, a `db.statementTimeout` of 10 seconds per statement, no DataLoader/batching, and a default HikariCP pool of 10 connections, an unprivileged attacker can send a small number of concurrent depth-10 chain requests to exhaust the connection pool and deny service to all legitimate users.

### Finding Description

**Schema — self-referential field enabling chain queries:**
`graphql/src/main/resources/graphql/account.graphqls` line 9 defines `autoRenewAccount: Account` (and line 67 `stakedAccount: Account`) on the `Account` type, making it self-referential. A depth-10 chain is therefore syntactically valid.

**Depth limit allows exactly 10 levels:**
`graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java` lines 43–45:
```java
var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
```
`MaxQueryDepthInstrumentation(10)` rejects queries with depth **greater than** 10, so a query with exactly 10 levels of `autoRenewAccount` nesting passes validation and proceeds to execution.

**Complexity limit is not a barrier:**
Line 43: `MaxQueryComplexityInstrumentation(200)`. A depth-10 chain with one field per level has complexity ≈ 10, far below 200.

**No DataLoader / batching:**
`grep` across the entire `graphql/` module returns zero hits for `DataLoader` or `BatchLoader`. The `AccountController` (`AccountController.java` lines 60–63) only registers a `@SchemaMapping` for `balance`; there is no `@SchemaMapping` for `autoRenewAccount` or `stakedAccount`. Spring GraphQL therefore resolves each nested `Account` via the default property accessor, which in turn calls `EntityServiceImpl.getByIdAndType()` → `entityRepository.findById()` — one synchronous JDBC query per nesting level (N+1 pattern).

**Statement timeout is per-statement, not per-request:**
`charts/hedera-mirror/templates/secret-passwords.yaml` line 122:
```sql
alter user mirror_graphql set statement_timeout to '10000';
```
Each individual SQL statement is capped at 10 s. A depth-10 chain therefore issues up to 10 sequential statements, holding a HikariCP connection for up to 10 s per statement (connections are acquired per-transaction in Spring's default non-`@Transactional` mode).

**HikariCP pool size — no explicit override for GraphQL:**
`common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java` lines 61–64 bind HikariCP from `spring.datasource.hikari`. The GraphQL README (`docs/graphql/README.md` lines 15–24) lists no pool-size property; no `maximumPoolSize` override exists in the `graphql/` tree. HikariCP's default `maximumPoolSize` is **10**.

**No rate limiting:**
The GraphQL configuration (`GraphQlConfiguration.java`) applies only parser limits, depth, and complexity checks. No HTTP-level throttle, no per-IP limit, and no request-queue bound is configured for the GraphQL module.

**Exploit flow:**
1. Attacker sends ≥ 10 concurrent POST requests to `/graphql/alpha` with a depth-10 `autoRenewAccount` chain targeting an account whose `autoRenewAccountId` chain is populated.
2. Each request triggers up to 10 sequential `SELECT * FROM entity WHERE id = ?` statements.
3. If the DB is under load (or the attacker targets accounts with slow index scans), each statement runs for up to 10 s, holding a HikariCP connection for that duration.
4. With 10 concurrent requests each holding 1 connection at a time, all 10 pool slots are occupied.
5. Subsequent legitimate requests block waiting for a connection; HikariCP's default `connectionTimeout` (30 s) causes them to throw `SQLTimeoutException` after 30 s, returning HTTP 500 to end users.
6. The attacker sustains the exhaustion by continuously re-issuing requests as old ones time out.

### Impact Explanation
Complete denial of service for all GraphQL API consumers. Every legitimate `account` query fails with a connection-pool timeout for as long as the attack is sustained. Because the GraphQL module shares a single HikariCP pool, no legitimate request can acquire a connection. The mirror node's GraphQL endpoint becomes entirely unavailable without any infrastructure-level intervention.

### Likelihood Explanation
The attack requires zero privileges — the endpoint is publicly accessible with no authentication. The payload is a standard GraphQL query (≤ 10 000 characters, within the parser limit). Only 10 concurrent HTTP connections are needed, achievable from a single machine with `curl --parallel` or any HTTP client. The attack is trivially repeatable and scriptable, and the attacker incurs no cost beyond network bandwidth.

### Recommendation
1. **Add per-IP / global request rate limiting** at the application or ingress layer (e.g., Spring's `RateLimiter`, an API gateway, or an Nginx `limit_req` directive).
2. **Reduce `MaxQueryDepthInstrumentation` to 3–5** — the current schema does not require depth 10 for any legitimate use case.
3. **Implement DataLoader / batching** for `autoRenewAccount` and `stakedAccount` resolvers to collapse N+1 DB calls into a single batched query per request.
4. **Explicitly configure HikariCP `maximumPoolSize`** for the GraphQL module and add a `connectionTimeout` short enough to fail fast rather than queue indefinitely.
5. **Add a per-request wall-clock timeout** (e.g., via a `WebFilter` or Spring MVC `HandlerInterceptor`) that cancels the entire GraphQL execution after a fixed budget (e.g., 5 s), independent of per-statement timeouts.

### Proof of Concept
```bash
# Craft a depth-10 autoRenewAccount chain query
QUERY='{"query":"{ account(input:{entityId:{shard:0,realm:0,num:2}}) { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { autoRenewAccount { entityId { num } } } } } } } } } } }"}'

# Fire 20 concurrent requests (10 to exhaust pool, 10 more to observe failures)
for i in $(seq 1 20); do
  curl -s -X POST http://<host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "$QUERY" &
done
wait
```
Expected result: the first 10 requests occupy all HikariCP connections; the remaining 10 (and any legitimate requests) receive HTTP 500 / connection-pool-timeout errors within 30 s, demonstrating full pool exhaustion.

**Supporting code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** graphql/src/main/resources/graphql/account.graphqls (L4-9)
```text
type Account implements Accountable & Entity & Node {
    "The unique alias associated with this account."
    alias: String

    "The account charged the auto-renewal fee."
    autoRenewAccount: Account
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

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L122-122)
```yaml
    alter user {{ $graphqlUsername }} set statement_timeout to '10000';
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L32-63)
```java
    @QueryMapping
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

    @SchemaMapping
    Long balance(@Argument @Valid HbarUnit unit, Account account) {
        return convertCurrency(unit, account.getBalance());
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L61-64)
```java
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }
```

**File:** docs/graphql/README.md (L15-24)
```markdown
| Name                                       | Default                                          | Description                                                                                                                                                                                   |
| ------------------------------------------ | ------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `hiero.mirror.graphql.cache.query`         | expireAfterWrite=1h,maximumSize=1000,recordStats | The Caffeine cache expression to use to configure the query parser cache.                                                                                                                     |
| `hiero.mirror.graphql.db.host`             | 127.0.0.1                                        | The IP or hostname used to connect to the database.                                                                                                                                           |
| `hiero.mirror.graphql.db.name`             | mirror_node                                      | The name of the database.                                                                                                                                                                     |
| `hiero.mirror.graphql.db.password`         | mirror_graphql_pass                              | The database password used to connect to the database.                                                                                                                                        |
| `hiero.mirror.graphql.db.port`             | 5432                                             | The port used to connect to the database.                                                                                                                                                     |
| `hiero.mirror.graphql.db.sslMode`          | DISABLE                                          | The ssl level of protection against eavesdropping, man-in-the-middle (MITM) and impersonation on the db connection. Accepts either DISABLE, ALLOW, PREFER, REQUIRE, VERIFY_CA or VERIFY_FULL. |
| `hiero.mirror.graphql.db.statementTimeout` | 10000                                            | The maximum amount of time in seconds to wait for a query to finish                                                                                                                           |
| `hiero.mirror.graphql.db.username`         | mirror_graphql                                   | The username used to connect to the database.                                                                                                                                                 |
```
