Based on my verification of the actual code, here is my assessment:

**Verified facts:**
- `HibernateConfiguration.java` lines 31–47 match exactly as quoted [1](#0-0) 
- `ContractCallContext.java` line 31 matches exactly as quoted [2](#0-1) 
- `Web3Properties.java` has `requestTimeout = Duration.ofSeconds(10L)` and **no** `statementTimeout` field [3](#0-2) 
- A grep of `web3/**/*.java` for `statementTimeout` returns **zero matches** — only `requestTimeout` appears in `Web3Properties.java`
- `docs/configuration.md` line 702 documents `hiero.mirror.web3.db.statementTimeout = 3000` but no `DbProperties` class exists in the web3 module [4](#0-3) 
- PostgreSQL role-level `statement_timeout` for `mirror_web3` is set to `'10000'` (10 s), equal to `requestTimeout` [5](#0-4) 

---

# Audit Report

## Title
Statement-Boundary-Only Timeout Check Allows DB Connection Exhaustion via Single Long-Running Query

## Summary
The `statementInspector()` in `HibernateConfiguration.java` enforces `requestTimeout` (10 s) only at Hibernate statement boundaries — it cannot interrupt a query already in flight. The documented `hiero.mirror.web3.db.statementTimeout = 3000 ms` property is never read or applied in the web3 Java codebase. The only effective per-query backstop is the PostgreSQL role-level `ALTER USER mirror_web3 SET statement_timeout TO '10000'`, which equals `requestTimeout`. A query submitted just before the 10-second mark can therefore run for an additional 10 seconds, holding a DB connection for up to ~20 seconds per request.

## Finding Description

**Root cause — three compounding failures:**

**1. `StatementInspector` is pre-dispatch only.**
The inspector fires before SQL is sent to the database. Once `return sql` executes at line 45, the query is in flight and the inspector has no further control.

```java
// HibernateConfiguration.java lines 31–47
StatementInspector statementInspector() {
    long timeout = web3Properties.getRequestTimeout().toMillis(); // 10,000 ms
    return sql -> {
        if (!ContractCallContext.isInitialized()) { return sql; }
        var startTime = ContractCallContext.get().getStartTime();
        long elapsed = System.currentTimeMillis() - startTime;
        if (elapsed >= timeout) {
            throw new QueryTimeoutException(...);
        }
        return sql;  // ← query dispatched; inspector cannot cancel it
    };
}
``` [1](#0-0) 

A query submitted at elapsed = 9,999 ms passes the check and is dispatched. It then runs until the PostgreSQL `statement_timeout` kills it — up to 10 more seconds.

**2. `db.statementTimeout = 3000 ms` is documented but never implemented.**
`docs/configuration.md` line 702 documents the property, but a full grep of `web3/**/*.java` for `statementTimeout` returns zero matches. No `DbProperties` class exists in the web3 module, and no Hikari `connectionInitSql` or JDBC URL parameter sets it. [4](#0-3) 

**3. PostgreSQL role-level `statement_timeout` equals `requestTimeout`.**
The only effective per-query backstop is:
```sql
alter user {{ $web3Username }} set statement_timeout to '10000';
``` [5](#0-4) 

This is 10,000 ms — identical to `requestTimeout` — providing zero additional protection against the race window.

**Effective maximum DB connection hold time per request:**
```
requestTimeout (10 s) + PostgreSQL statement_timeout (10 s) = up to 20 s
```

## Impact Explanation
DB connection pool exhaustion causes all legitimate contract call requests to queue or fail with connection timeout errors, rendering the web3 API unavailable or severely degraded. The Grafana alert `Web3HighDBConnections` fires at ~75% pool utilization, meaning observable impact occurs well before full exhaustion. At 20 s per connection hold, a modest number of concurrent slow requests can saturate the pool.

## Likelihood Explanation
No authentication is required to call `POST /api/v1/contracts/call`. The rate limiter throttles request rate but does not limit concurrent slow requests. An attacker needs only to identify or deploy a contract whose execution path triggers a slow Hibernate query (e.g., a historical block query against a large table) and submit it repeatedly. The attack is repeatable, requires no special privileges, and can be automated with a simple HTTP client.

## Recommendation

1. **Implement `db.statementTimeout`**: Create a `DbProperties` class in the web3 module that reads `hiero.mirror.web3.db.statementTimeout` and applies it via Hikari's `connectionInitSql` (e.g., `SET statement_timeout = 3000`) or as a JDBC URL parameter. This ensures the PostgreSQL-level timeout is shorter than `requestTimeout`, bounding the race window.

2. **Reduce PostgreSQL role-level timeout**: Change `ALTER USER mirror_web3 SET statement_timeout TO '10000'` to a value matching the intended `statementTimeout` (e.g., `3000`), so the backstop is meaningful even if the application-level setting is misconfigured. [6](#0-5) 

3. **Add a connection-level timeout on acquisition**: Configure Hikari's `connectionTimeout` to fail fast when the pool is under pressure, preventing request threads from blocking indefinitely waiting for a connection.

## Proof of Concept

1. Deploy or identify a contract whose execution triggers a slow SQL query (e.g., a historical storage slot scan across a large table).
2. Submit ~30 concurrent `POST /api/v1/contracts/call` requests targeting that contract.
3. Each request's EVM execution consumes ~9.9 s before issuing the first Hibernate query; the inspector passes the query through (elapsed < 10,000 ms).
4. The dispatched query runs for up to 10 more seconds before PostgreSQL kills it.
5. Each request holds a DB connection for ~20 s. With sufficient concurrency, the pool is exhausted.
6. All subsequent legitimate requests receive connection timeout errors; the web3 API is effectively unavailable.

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

**File:** web3/src/main/java/org/hiero/mirror/web3/common/ContractCallContext.java (L30-31)
```java
    @Getter
    private final long startTime = System.currentTimeMillis();
```

**File:** web3/src/main/java/org/hiero/mirror/web3/Web3Properties.java (L19-20)
```java
    @DurationMin(seconds = 1L)
    private Duration requestTimeout = Duration.ofSeconds(10L);
```

**File:** docs/configuration.md (L702-702)
```markdown
| `hiero.mirror.web3.db.statementTimeout`                      | 3000                                               | The number of milliseconds to wait before timing out a query statement                                                                                                                           |
```

**File:** charts/hedera-mirror/templates/secret-passwords.yaml (L121-127)
```yaml
    -- Set statement timeouts
    alter user {{ $graphqlUsername }} set statement_timeout to '10000';
    alter user {{ $grpcUsername }} set statement_timeout to '10000';
    alter user {{ $restUsername }} set statement_timeout to '20000';
    alter user {{ $restJavaUsername }} set statement_timeout to '20000';
    alter user {{ $rosettaUsername }} set statement_timeout to '10000';
    alter user {{ $web3Username }} set statement_timeout to '10000';
```
