### Title
Undeclared `statementTimeout` for rest-java DSLContext Enables Connection-Pool Starvation via Unbounded Query Duration

### Summary
The `findAll` method in `NftAllowanceRepositoryCustomImpl` executes jOOQ queries through a `DSLContext` that has no server-side query timeout configured. The `hiero.mirror.restJava.db.statementTimeout` property is documented and exists in configuration metadata but is never read or applied anywhere in the rest-java application code, leaving every DSLContext-issued query without an application-enforced time bound. An unprivileged attacker can submit concurrent requests that hold database connections open long enough to exhaust the HikariCP pool and partition the application from the database.

### Finding Description

**Exact code path:**

`NftAllowanceRepositoryCustomImpl.java` lines 37–47 — the `findAll` method issues a jOOQ query directly via the injected `DSLContext`:

```java
return dslContext
        .selectFrom(NFT_ALLOWANCE)
        .where(condition)
        .orderBy(SORT_ORDERS.get(new OrderSpec(byOwner, request.getOrder())))
        .limit(request.getLimit())
        .fetchInto(NftAllowance.class);
```

**Root cause — `statementTimeout` is a dead property for rest-java:**

`RestJavaConfiguration.java` lines 37–39 is the only place the jOOQ `DefaultConfigurationCustomizer` is registered:

```java
return c -> c.set(domainRecordMapperProvider).settings().withRenderSchema(false);
```

No `queryTimeout`, `Settings.withQueryTimeout`, or `ExecuteListener` with a timeout is set. A grep for `statementTimeout`, `connectionInitSql`, `statement_timeout`, `queryTimeout`, or `setQueryTimeout` across the entire `rest-java` source tree returns **zero matches**. The property `hiero.mirror.restJava.db.statementTimeout` (default 10 000 ms) is documented in `docs/configuration.md` line 630 and appears in the Helm secret template (`secret-passwords.yaml` line 125 sets the PostgreSQL role-level timeout to 20 000 ms), but **no Java code in rest-java reads or applies this value** — not to the HikariConfig `connectionInitSql`, not to the DSLContext, not to any JDBC statement.

`CommonConfiguration.java` lines 60–95 builds the `HikariDataSource` from `spring.datasource.hikari` properties only; no `connectionInitSql` carrying `SET statement_timeout` is present.

**Failed assumption:** operators and reviewers assume `hiero.mirror.restJava.db.statementTimeout` is enforced at the application layer. It is not. The only real guard is the PostgreSQL role-level `statement_timeout` set by the Helm chart, which is absent in non-Helm deployments and is 20 seconds even when present — long enough to exhaust a small pool.

### Impact Explanation

HikariCP's default maximum pool size is 10 connections. With no application-enforced timeout, each request to the NFT allowances endpoint holds a connection for the full duration of the query (up to the PostgreSQL role-level 20 s in Helm deployments, or indefinitely in bare deployments). Sending 10–15 concurrent slow requests exhausts the pool. Subsequent requests block waiting for a connection until `connectionTimeout` (HikariCP default 30 s) expires, at which point they throw `SQLTransientConnectionException`. This effectively partitions the rest-java service from the database for all endpoints that use the same pool, not just the NFT allowances endpoint — a full service-level DoS.

### Likelihood Explanation

No authentication is required to call the NFT allowances endpoint. The `limit` parameter caps the result-set row count but does not bound query execution time; complex `getBoundConditions` predicates on a large `nft_allowance` table can produce slow sequential scans regardless of the row limit. A single attacker with a script sending ~15 concurrent HTTP requests can reliably trigger pool exhaustion. The attack is repeatable and requires no special knowledge beyond the public API schema.

### Recommendation

1. **Wire the existing property**: In `RestJavaConfiguration.java`, read `hiero.mirror.restJava.db.statementTimeout` and apply it to the jOOQ configuration:
   ```java
   return c -> c.set(domainRecordMapperProvider)
                .settings()
                .withRenderSchema(false)
                .withQueryTimeout((int)(statementTimeoutMs / 1000));
   ```
   or set it via `connectionInitSql` on the `HikariConfig`:
   ```java
   hikariConfig.setConnectionInitSql(
       "SET statement_timeout = " + statementTimeoutMs);
   ```
2. **Reduce the default**: 10 000 ms is generous; align with the web3 default of 3 000 ms.
3. **Add a Hikari `connectionTimeout`** guard so pool-wait failures fail fast rather than blocking threads.
4. **Rate-limit** the allowances endpoint at the ingress/gateway layer (the Helm chart already has `maxRatePerEndpoint: 250` for the GCP gateway, but this does not apply to all deployment topologies).

### Proof of Concept

```bash
# Assumes a rest-java instance with a large nft_allowance table.
# Send 15 concurrent requests; each holds a DB connection for the full query duration.
for i in $(seq 1 15); do
  curl -s "http://<host>/api/v1/accounts/0.0.1234/allowances/nfts?limit=100&order=asc" &
done
wait

# Subsequent requests will fail with connection pool timeout:
curl -v "http://<host>/api/v1/accounts/0.0.1234/allowances/nfts"
# Expected: 500 / SQLTransientConnectionException: Unable to acquire JDBC Connection
```