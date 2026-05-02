### Title
GraphQL Complexity Limit Allows Unauthenticated Connection Pool Exhaustion via Aliased `findByAlias` Queries During Network Partition

### Summary
The GraphQL endpoint enforces a complexity limit of 200 but has no per-request rate limiting, no DB statement timeout, and no authentication requirement. An unauthenticated attacker can craft a single GraphQL request containing up to ~100 aliased `account(input: {alias: ...})` queries, each triggering a synchronous `findByAlias` DB call. During a network partition, each call holds a HikariCP connection for the full socket timeout duration, and a small number of concurrent attacker requests exhausts the connection pool, denying service to all legitimate users.

### Finding Description

**Exact code path:**

`AccountController.account()` is the `@QueryMapping` handler: [1](#0-0) 

It delegates to `EntityServiceImpl.getByAliasAndType()`: [2](#0-1) 

Which calls `EntityRepository.findByAlias()` — a native SQL query with no caching, no timeout, and no pagination: [3](#0-2) 

**Root cause — failed assumption:**

`GraphQlConfiguration` sets a complexity limit of 200 and depth limit of 10: [4](#0-3) 

The design assumes complexity=200 bounds resource use. The failed assumption is that each complexity unit maps to bounded, fast work. In reality, graphql-java's default complexity calculator assigns **1 per field selection**. A query like:

```graphql
{
  a1: account(input: {alias: "AAAAAAA"}) { id }
  a2: account(input: {alias: "BBBBBBB"}) { id }
  ...
  a100: account(input: {alias: "ZZZZZZZ"}) { id }
}
```

consumes 200 complexity units (2 per alias: `account` + `id`) and is accepted. Spring GraphQL executes each top-level field resolver sequentially, so this triggers **100 sequential `findByAlias` DB calls** within a single HTTP request.

**Why existing checks fail:**

- The complexity limit of 200 is the only guard; it is not calibrated to DB call count.
- There is **no rate limiting** on the GraphQL module — unlike the `web3` module which has `ThrottleManager`/`ThrottleConfiguration`, the `graphql` module has no equivalent. [5](#0-4) 
- There is **no DB statement timeout** configured for the graphql module (no `application.yml` with `spring.datasource.hikari` or `statement_timeout` found).
- The `EntityRepository` in the graphql module has **no `@Cacheable`** annotation, unlike the `web3` module's `EntityRepository` which caches alias lookups. [6](#0-5) 
- No authentication is required; the endpoint is public.

**During a network partition:**

HikariCP is the connection pool (configured via `CommonConfiguration`): [7](#0-6) 

When the DB is unreachable, each `findByAlias` call acquires a connection from the pool and blocks until the TCP socket timeout (typically 30s+). With the default HikariCP pool size of 10, **10 concurrent attacker requests** (each with 100 aliased queries) exhaust the pool. Subsequent legitimate requests receive `Connection is not available, request timed out` errors.

### Impact Explanation

**Concrete impact:** Complete denial of service for all GraphQL users. The connection pool is exhausted; every legitimate `account` query fails with a connection acquisition timeout. The attack is amplified: each attacker HTTP request holds 1 DB connection for up to `100 × socket_timeout` seconds sequentially, meaning very few concurrent attacker connections are needed to saturate the pool. Recovery requires either the network partition to resolve or the attacker to stop sending requests.

**Severity:** High. The GraphQL service becomes entirely unavailable to legitimate users for the duration of the attack. No data is modified, but availability is fully compromised.

### Likelihood Explanation

**Attacker capability:** Zero — no account, no API key, no authentication of any kind is required. The endpoint is publicly accessible at `/graphql/alpha`.

**Feasibility:** Trivially reproducible with a single `curl` or any HTTP client. The attacker needs only to know the GraphQL schema (which is introspectable by default) to construct the aliased query.

**Repeatability:** The attack is stateless and can be repeated indefinitely. A single attacker with modest bandwidth can sustain the DoS.

### Recommendation

1. **Add a DB statement timeout** for the graphql datasource (e.g., `spring.datasource.hikari.connection-init-sql=SET statement_timeout=5000` or via PostgreSQL `options=-c statement_timeout=5000` in the JDBC URL). This bounds how long any single `findByAlias` call can hold a connection.
2. **Add per-IP or global rate limiting** to the GraphQL endpoint, analogous to the `ThrottleManager` used in the `web3` module.
3. **Recalibrate complexity weights**: assign a higher complexity cost (e.g., 10) to the `account` field so that the number of DB-triggering queries per request is bounded to a small number (e.g., ≤20).
4. **Limit aliased root field repetition**: reject or limit queries where the same root field appears more than N times via a custom instrumentation.
5. **Add caching** to `EntityRepository.findByAlias()` in the graphql module (as done in the `web3` module) to reduce DB round-trips for repeated alias lookups.

### Proof of Concept

**Preconditions:** Network partition between the GraphQL service and PostgreSQL (e.g., `iptables -A OUTPUT -p tcp --dport 5432 -j DROP` on the app host, or a firewall rule). No credentials needed.

**Steps:**

1. Construct a GraphQL query with 100 aliased `account` queries at complexity 200:

```graphql
{
  a001: account(input: {alias: "AAAAAAAAAAAAAAAA"}) { id }
  a002: account(input: {alias: "BBBBBBBBBBBBBBBB"}) { id }
  # ... repeat to a100
}
```

2. Send 10–15 concurrent HTTP POST requests to `/graphql/alpha` with the above body (Content-Type: `application/json`, body: `{"query": "{ a001: account(...) { id } ... }"}`):

```bash
for i in $(seq 1 15); do
  curl -s -X POST http://TARGET/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ a001: account(input:{alias:\"AAAAAAA\"}) { id } a002: account(input:{alias:\"BBBBBBB\"}) { id } ... }"}' &
done
wait
```

3. **Observe:** Legitimate requests to `/graphql/alpha` immediately return errors such as `HikariPool - Connection is not available, request timed out after 30000ms`. The service is unavailable for the duration of the attack.

### Citations

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L11-14)
```java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-49)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L60-64)
```java
    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }
```
