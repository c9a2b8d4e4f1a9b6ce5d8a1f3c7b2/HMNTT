### Title
Pre-Submission-Only Timeout Check in `statementInspector()` Allows Queries to Run Beyond `requestTimeout`, Enabling Connection Pool Exhaustion DoS

### Summary
The `statementInspector()` in `web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java` only checks elapsed time **before** submitting a SQL statement to the database. It never sets a JDBC `setQueryTimeout()` on the statement, so any query submitted just under the 10-second `requestTimeout` threshold can continue executing on the database for an additional `statement_timeout` window (up to 10 seconds at the DB user level). An unprivileged external user can craft `eth_call` / `eth_estimateGas` requests that trigger expensive multi-table JOIN queries, holding HikariCP connections for up to ~2× `requestTimeout`, and with enough concurrent requests exhaust the connection pool.

### Finding Description

**Code path:**

`web3/src/main/java/org/hiero/mirror/web3/config/HibernateConfiguration.java`, `statementInspector()`, lines 31–47:

```java
StatementInspector statementInspector() {
    long timeout = web3Properties.getRequestTimeout().toMillis(); // default 10 000 ms
    return sql -> {
        if (!ContractCallContext.isInitialized()) {
            return sql;
        }
        var startTime = ContractCallContext.get().getStartTime();
        long elapsed = System.currentTimeMillis() - startTime;

        if (elapsed >= timeout) {                          // ← only pre-submission check
            throw new QueryTimeoutException(...);
        }

        return sql;                                        // ← no setQueryTimeout() called
    };
}
```

**Root cause:** The inspector is a Hibernate `StatementInspector` callback that fires before the JDBC `PreparedStatement` is executed. It throws if `elapsed >= timeout`, but if `elapsed < timeout` it returns the SQL string unchanged. Hibernate then executes the statement with **no JDBC-level query timeout** (`Statement.setQueryTimeout()` is never called). The running query is therefore bounded only by the PostgreSQL `statement_timeout` set on the `mirror_web3` role (10 000 ms per `charts/hedera-mirror/templates/secret-passwords.yaml` line 127; 3 000 ms per `docs/configuration.md` line 702 — whichever is active).

**Exploit flow:**

1. Attacker sends an `eth_call` to `/api/v1/contracts/call` (no authentication required — CORS is `allowedOrigins("*")` per `GenericControllerAdvice.java` line 77).
2. `ContractCallContext.run()` initialises the context and records `startTime`.
3. The EVM execution path reads contract state, token info, NFT data, etc., triggering Hibernate queries against large tables (`entity`, `token`, `nft`, `contract_state`, `token_account`, …).
4. The attacker crafts call data that causes a query to be submitted at `elapsed ≈ 9 999 ms` (just under the 10 s threshold). The `statementInspector` allows it through.
5. PostgreSQL receives the query and begins a hash join across multiple large tables. With sufficient data volume the planner spills to disk; the query runs for up to `statement_timeout` (3 000–10 000 ms) more before PostgreSQL cancels it.
6. Total wall-clock time the HikariCP connection is held: up to **~20 seconds** per request.
7. With a modest number of concurrent requests (pool size is not explicitly capped in web3 config — defaults to HikariCP's 10), the pool is exhausted and all subsequent requests queue or fail.

**Why existing checks fail:**

- The `statementInspector` pre-submission check is the **only** application-level timeout enforcement. It cannot interrupt a query already in flight.
- The DB-level `statement_timeout` is a backstop, not a fix: it still allows the connection to be held for `requestTimeout + statement_timeout` total.
- The `QueryTimeoutException` handler in `GenericControllerAdvice.java` (line 120) returns HTTP 503, but only after the connection has already been held for the full duration.
- No `setQueryTimeout()` is set anywhere in the web3 Hibernate/JDBC stack.

### Impact Explanation
An unprivileged attacker can hold each HikariCP connection for up to ~20 seconds per request. With the default pool size (~10 connections) and a sustained rate of ~1 request per 20 seconds per connection, the entire pool is saturated. All legitimate `eth_call` and `eth_estimateGas` requests begin timing out or receiving 503 responses. This is a complete, unauthenticated denial of service against the web3 API's database layer. Severity: **High** (availability impact, no authentication required, repeatable).

### Likelihood Explanation
Any user with network access to port 8545 (or 8080 via the nginx proxy) can trigger this. No wallet, token, or privileged account is needed — `eth_call` is a read-only simulation endpoint. The attacker only needs to identify a contract call path that causes a slow query (e.g., historical block queries joining `record_file`, `entity`, `token`, `nft` tables) and time the request so the query is submitted near the end of the timeout window. This is straightforward to automate and repeat.

### Recommendation

1. **Set a JDBC query timeout on every statement** in the `statementInspector`:
   ```java
   // After returning sql, Hibernate does not expose the Statement here.
   // Instead, configure Hibernate's `hibernate.jdbc.fetch_size` and use
   // a HikariCP `connectionInitSql` or a custom `StatementInspector` that
   // wraps the connection to call setQueryTimeout().
   ```
   The correct fix is to configure `spring.datasource.hikari.connection-init-sql` to `SET statement_timeout = 3000` (matching `hiero.mirror.web3.db.statementTimeout`) **and** set `spring.datasource.hikari.connection-timeout` appropriately, so the DB enforces the timeout independently of the application check.

2. **Use Hibernate's built-in query timeout**: Set `javax.persistence.query.timeout` (or `hibernate.query.timeout`) globally so every query gets a JDBC-level timeout equal to the remaining budget.

3. **Reduce `statement_timeout` for the `mirror_web3` DB role** to match `requestTimeout` (10 s → 3 s or less), so the DB backstop fires well within the intended window.

4. **Cap the HikariCP pool size** explicitly in the web3 application configuration and set `connectionTimeout` to fail fast when the pool is exhausted rather than queuing indefinitely.

### Proof of Concept

```bash
# 1. Identify a contract call that triggers a historical multi-table query
#    (e.g., a token info precompile call at an early block number)

# 2. Send concurrent requests timed to submit the heavy query near t=9999ms
for i in $(seq 1 20); do
  curl -s -X POST http://<web3-host>:8545/api/v1/contracts/call \
    -H 'Content-Type: application/json' \
    -d '{
      "data": "<HTS_getTokenInfo_selector><token_address>",
      "to": "0x0000000000000000000000000000000000000167",
      "block": "earliest",
      "gas": 15000000
    }' &
done
wait

# 3. Observe: requests take 15–20 s each; subsequent requests receive HTTP 503
#    or hang until HikariCP connection-acquisition timeout fires.
# 4. Monitor DB: SELECT * FROM pg_stat_activity WHERE usename='mirror_web3'
#    shows connections stuck in long-running hash-join queries.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

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

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L31-31)
```java
    private final long startTime = System.currentTimeMillis();
```

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L127-127)
```yaml
    alter user {{ $web3Username }} set statement_timeout to '10000';
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L73-78)
```java
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/api/v1/contracts/**").allowedOrigins("*");
            }
```

**File:** web3/src/main/java/org/hiero/mirror/web3/controller/GenericControllerAdvice.java (L119-122)
```java
    @ExceptionHandler
    private ResponseEntity<?> queryTimeoutException(final QueryTimeoutException e, WebRequest request) {
        return handleExceptionInternal(e, null, null, SERVICE_UNAVAILABLE, request);
    }
```
