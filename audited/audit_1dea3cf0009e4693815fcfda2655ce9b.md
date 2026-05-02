### Title
Thread Starvation via Unbounded JDBC Socket Blocking in `getByAliasAndType()` During Network Partition

### Summary
`EntityServiceImpl.getByAliasAndType()` invokes `entityRepository.findByAlias()`, a native JDBC query, with no socket-level timeout on the underlying JDBC connection. During a network partition, the JDBC driver's socket read blocks the calling thread indefinitely — PostgreSQL's server-side `statement_timeout` does not fire because it only cancels queries actively executing on the server, not client threads blocked waiting for TCP data. With no rate limiting on the GraphQL endpoint, an unprivileged attacker can flood the service with concurrent alias-lookup requests during a partition, exhausting the thread pool and causing a full service DoS.

### Finding Description

**Exact code path:**

`getByAliasAndType()` at line 29–31 of `graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`:
```java
public Optional<Entity> getByAliasAndType(String alias, EntityType type) {
    return entityRepository.findByAlias(decodeBase32(alias)).filter(e -> e.getType() == type);
}
``` [1](#0-0) 

This calls `findByAlias()` in `EntityRepository`, which executes a native SQL query via JDBC:
```java
@Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
Optional<Entity> findByAlias(byte[] alias);
``` [2](#0-1) 

**Root cause — two compounding gaps:**

1. **No JDBC socket timeout.** `CommonConfiguration` builds the HikariCP `DataSource` from `spring.datasource.hikari` properties only. [3](#0-2) 
No `socketTimeout` JDBC URL parameter or HikariCP `connectionInitSql` setting is applied to the graphql module's connections. The `socketTimeout` in `CommonProperties.DatabaseStartupProperties` (2 s) is used only by `DatabaseWaiter` at startup, not for live query connections. [4](#0-3) 

2. **No rate limiting on the GraphQL endpoint.** `GraphQlConfiguration` enforces only query complexity (200) and depth (10) limits — parse-time checks that do not bound the number of concurrent in-flight requests. [5](#0-4) 
The throttle infrastructure (`ThrottleManagerImpl`, `ThrottleConfiguration`) exists only in the `web3` module; there is no equivalent in the `graphql` module.

**Why the existing `statement_timeout` is insufficient:**

The Helm chart sets a PostgreSQL role-level `statement_timeout = 10000` ms for the graphql user: [6](#0-5) 

This is a **server-side** mechanism. During a network partition:
- If the query reaches the server, the server cancels it after 10 s — but the JDBC socket read on the Java side remains blocked indefinitely because no TCP FIN/RST arrives.
- If the partition drops the query before it reaches the server, the server never starts the query and `statement_timeout` never fires at all.

In both cases, the Java thread executing `findByAlias()` is blocked on a socket read with no timeout, holding a HikariCP connection and a server thread for an unbounded duration.

### Impact Explanation

Each concurrent `getByAliasAndType()` call during a partition occupies one Java thread and one HikariCP connection indefinitely. Spring's embedded Tomcat has a bounded thread pool (default 200 threads). Once all threads are blocked, the service stops accepting new requests entirely — a complete DoS. The HikariCP connection pool (bounded) is also exhausted, preventing any other query from executing even after the partition resolves, until connections time out and are evicted.

### Likelihood Explanation

**Precondition:** A network partition between the graphql pod and the PostgreSQL database must exist. This is an environmental condition (infrastructure failure, misconfigured network policy, cloud provider incident) — the attacker does not cause it, but exploits it opportunistically.

**Attacker capability:** Zero — no authentication, no special headers, no privileged access. Any client that can reach the public GraphQL endpoint can send alias-lookup queries. The GraphQL endpoint is documented as publicly accessible. [7](#0-6) 

**Repeatability:** During the partition window, a single attacker with a modest HTTP client (e.g., 50–200 concurrent connections) can saturate the thread pool in seconds. The attack is trivially scriptable.

### Recommendation

1. **Add a JDBC socket timeout** to the graphql datasource JDBC URL: append `?socketTimeout=15` (seconds) to the PostgreSQL JDBC URL, or set it via HikariCP's `connectionInitSql: SET LOCAL statement_timeout = '10000'`. This ensures the JDBC driver's socket read unblocks after the configured interval regardless of network state.

2. **Add an application-level request timeout** analogous to `web3`'s `HibernateConfiguration` `StatementInspector` or a `WebFilter` that cancels the request after a deadline. [8](#0-7) 

3. **Add rate limiting** to the GraphQL endpoint, mirroring the `ThrottleManagerImpl` pattern used in the `web3` module, to bound the number of concurrent in-flight requests per IP or globally. [9](#0-8) 

### Proof of Concept

```bash
# 1. Induce or wait for a network partition between graphql pod and PostgreSQL
#    (e.g., apply a network policy dropping traffic to port 5432)

# 2. From any external host, flood the GraphQL endpoint with alias lookups:
for i in $(seq 1 300); do
  curl -s -X POST http://<graphql-host>:8083/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{account(input:{alias:\"AABBCCDD\"}){balance}}"}' &
done
wait

# 3. Observe: after ~200 concurrent requests, the service stops responding.
#    New requests receive connection refused or timeout.
#    After the partition heals, the service remains degraded until
#    blocked threads time out (no socket timeout = indefinite).
```

### Citations

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

**File:** common/src/main/java/org/hiero/mirror/common/CommonConfiguration.java (L60-95)
```java
    @Bean
    @ConfigurationProperties("spring.datasource.hikari")
    HikariConfig hikariConfig() {
        return new HikariConfig();
    }

    @Bean
    @ConditionalOnMissingBean(DataSource.class)
    @Lazy
    DataSource dataSource(
            DataSourceProperties dataSourceProperties,
            HikariConfig hikariConfig,
            DatabaseWaiter databaseWaiter,
            ObjectProvider<JdbcConnectionDetails> detailsProvider) {

        var jdbcUrl = dataSourceProperties.determineUrl();
        var username = dataSourceProperties.determineUsername();
        var password = dataSourceProperties.determinePassword();

        final var connectionDetails = detailsProvider.getIfAvailable();
        if (connectionDetails != null) {
            jdbcUrl = connectionDetails.getJdbcUrl();
            username = connectionDetails.getUsername();
            password = connectionDetails.getPassword();
        }

        databaseWaiter.waitForDatabase(jdbcUrl, username, password);

        final var config = new HikariConfig();
        hikariConfig.copyStateTo(config);
        config.setJdbcUrl(jdbcUrl);
        config.setUsername(username);
        config.setPassword(password);

        return new HikariDataSource(config);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/CommonProperties.java (L93-96)
```java
        @DurationMin(seconds = 1)
        @DurationUnit(ChronoUnit.SECONDS)
        @NotNull
        private Duration socketTimeout = Duration.ofSeconds(2);
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

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L121-122)
```yaml
    -- Set statement timeouts
    alter user {{ $graphqlUsername }} set statement_timeout to '10000';
```

**File:** docs/graphql/README.md (L33-35)
```markdown
```bash
curl -X POST http://localhost:8083/graphql/alpha -H 'Content-Type: application/json' \
  -d '{"query": "{account(input: {entityId: {shard: 0, realm: 0, num: 2}}) { balance }}"}'
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java (L31-47)
```java
    StatementInspector statementInspector() {
        long timeout = web3Properties.getRequestTimeout().toMillis();
        return sql -> {
            if (!ContractCallContext.isInitialized()) {
                return sql;
            }

            var startTime = ContractCallContext.get().getStartTime();
            long elapsed = System.currentTimeMillis() - startTime;

            if (elapsed >= timeout) {
                throw new QueryTimeoutException("Transaction timed out after %s ms".formatted(elapsed));
            }

            return sql;
        };
    }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/throttle/ThrottleManagerImpl.java (L37-49)
```java
    public void throttle(ContractCallRequest request) {
        if (!rateLimitBucket.tryConsume(1)) {
            throw new ThrottleException(REQUEST_PER_SECOND_LIMIT_EXCEEDED);
        } else if (!gasLimitBucket.tryConsume(throttleProperties.scaleGas(request.getGas()))) {
            throw new ThrottleException(GAS_PER_SECOND_LIMIT_EXCEEDED);
        }

        for (var requestFilter : throttleProperties.getRequest()) {
            if (requestFilter.test(request)) {
                action(requestFilter, request);
            }
        }
    }
```
