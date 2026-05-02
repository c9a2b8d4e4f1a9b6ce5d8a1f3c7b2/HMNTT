### Title
Unauthenticated Connection Pool Exhaustion via Concurrent Airdrop Requests in `getAirdrops()`

### Summary
The `rest-java` service exposes `/api/v1/accounts/{id}/airdrops/outstanding` and `/api/v1/accounts/{id}/airdrops/pending` with no rate limiting. Each request holds a HikariCP connection for the sequential duration of `entityService.lookup()` and `repository.findAll()`. Because the `rest-java` module sets no explicit `maximumPoolSize` (defaulting to HikariCP's 10) and has no per-IP or global request throttle, an unprivileged attacker can exhaust the pool with a small number of concurrent requests, causing all subsequent requests to queue and time out.

### Finding Description
**Code path:**
`rest-java/src/main/java/org/hiero/mirror/restjava/service/TokenAirdropServiceImpl.java`, lines 19–22:
```java
public Collection<TokenAirdrop> getAirdrops(TokenAirdropRequest request) {
    var id = entityService.lookup(request.getAccountId());   // DB connection held
    return repository.findAll(request, id);                  // DB connection held
}
```
Both calls execute synchronously on the same thread and hold a HikariCP connection for their combined duration.

**Root cause — three compounding gaps:**

1. **No rate limiting in `rest-java`**: The throttle infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`, `ThrottleProperties`) exists exclusively in the `web3` module. The `rest-java` config directory contains only `MetricsFilter`, `LoggingFilter`, `WebMvcConfiguration`, and `RestJavaConfiguration` — none of which implement request throttling or concurrency limits.

2. **No explicit pool size configured**: `CommonConfiguration` creates the `HikariDataSource` from `spring.datasource.hikari` properties. The `rest-java` documentation lists no `spring.datasource.hikari.maximum-pool-size` override, leaving HikariCP at its default of **10 connections**.

3. **Statement timeout does not prevent pool exhaustion**: The documented `hiero.mirror.restJava.db.statementTimeout` default is **10,000 ms**. An attacker needs only 10 concurrent requests, each holding a connection for up to 10 seconds, to keep the pool fully occupied continuously.

**Why existing checks fail:**
- `statementTimeout = 10s` limits per-query duration but does not reduce concurrency; 10 simultaneous slow queries still saturate a pool of 10.
- HikariCP's `connectionTimeout` (default 30 s) causes queued requests to fail with `SQLTransientConnectionException`, not to be rejected early — meaning the Tomcat thread pool (default 200 threads) can accumulate hundreds of waiting threads before any request is rejected.
- PgBouncer is configured for `mirror_rest` and `mirror_web3` users in the Helm values, but `mirror_rest_java` is **not listed** in the pgbouncer users section, so rest-java connections go directly to PostgreSQL without an additional pooling layer.

### Impact Explanation
When the 10-connection pool is exhausted, every subsequent request to any `rest-java` endpoint (not just airdrops) blocks waiting for a connection. After `connectionTimeout` (30 s), callers receive 500 errors. The application tier is functionally partitioned from the database for the duration of the attack. Because the Tomcat thread pool (200 threads) is 20× larger than the DB pool, the attacker can sustain the exhaustion with only 10 concurrent HTTP connections while the remaining 190 Tomcat threads pile up waiting. This is a complete service-level denial of the `rest-java` API.

### Likelihood Explanation
The attack requires zero authentication, zero special knowledge, and only ~10 concurrent HTTP connections. The endpoints are publicly documented. Any script-kiddie with `curl` or `ab` (Apache Bench) can reproduce it. The attack is repeatable, stateless, and requires no persistent state on the attacker's side. The only practical barrier is network-level rate limiting (e.g., an API gateway or WAF), which is not enforced in the application code itself.

### Recommendation
1. **Add rate limiting to `rest-java`**: Port the `web3` module's `ThrottleConfiguration`/`ThrottleManagerImpl` pattern (bucket4j) to `rest-java`, or add a servlet filter that enforces a global and/or per-IP requests-per-second limit on all `/api/v1/` endpoints.
2. **Set an explicit `maximumPoolSize`**: Configure `spring.datasource.hikari.maximum-pool-size` explicitly in `rest-java`'s application configuration and document it alongside the other `hiero.mirror.restJava.db.*` properties.
3. **Add PgBouncer coverage for `mirror_rest_java`**: Add `mirror_rest_java` to the pgbouncer users section in the Helm values to provide a second layer of connection pooling.
4. **Enforce Tomcat concurrency limits**: Set `server.tomcat.max-threads` and `server.tomcat.accept-count` to values proportional to the DB pool size to prevent thread pile-up.

### Proof of Concept
```bash
# Exhaust the 10-connection HikariCP pool with 12 concurrent requests
# No authentication required
for i in $(seq 1 12); do
  curl -s "http://<rest-java-host>/api/v1/accounts/0.0.1234/airdrops/outstanding" &
done
wait

# All subsequent requests to any rest-java endpoint now fail with 500
# (HikariCP: Connection is not available, request timed out after 30000ms)
curl -v "http://<rest-java-host>/api/v1/accounts/0.0.5678/airdrops/pending"
# Expected: HTTP 500, SQLTransientConnectionException
```
Sustaining the flood at ≥10 concurrent requests per 10-second window keeps the pool permanently exhausted.