### Title
Connection Pool Exhaustion via Unbounded Query Hang on `/api/v1/network/stake` During DB Network Partition

### Summary
The `NetworkStakeRepository.findLatest()` method executes a native SQL query with a correlated subquery against the `network_stake` table. During a database network partition, JDBC connections block indefinitely on socket reads because no socket-level timeout is configured for the runtime connection pool. Since the `/api/v1/network/stake` endpoint has no rate limiting in the rest-java module, any unauthenticated attacker can send concurrent requests during a partition to exhaust all HikariCP pool threads, causing a full REST API denial-of-service.

### Finding Description

**Exact code path:**

`NetworkController.getNetworkStake()` (line 127–130) calls `networkService.getLatestNetworkStake()`, which calls `networkStakeRepository.findLatest()`:

```java
// NetworkStakeRepository.java lines 12–19
@Query(value = """
    select *
    from network_stake
    where consensus_timestamp = (
        select max(consensus_timestamp) from network_stake
    )
    """, nativeQuery = true)
Optional<NetworkStake> findLatest();
```

**Root cause — no socket timeout on runtime JDBC connections:**

`CommonConfiguration` builds the HikariCP `DataSource` from `spring.datasource.hikari` properties at runtime. The `socketTimeout` found in `CommonProperties.DatabaseStartupProperties` (2 s) is used exclusively by `DatabaseWaiter` during startup, not applied to the runtime pool. No `socketTimeout` JDBC URL parameter or HikariCP `connectionTimeout`-equivalent for in-flight queries is set for the live pool. When a network partition occurs, the JDBC driver blocks indefinitely on `socket.read()` waiting for a PostgreSQL response that will never arrive.

**Why the existing `statement_timeout` is insufficient:**

The Helm chart sets `alter user mirror_rest_java set statement_timeout to '20000'` (20 s). This is a server-side PostgreSQL setting. When the network is partitioned, the PostgreSQL server fires the timeout and sends a cancellation error — but that error packet cannot traverse the severed network path. The JDBC thread remains blocked on the socket read, holding the HikariCP connection open indefinitely.

**No rate limiting on the endpoint:**

The throttling infrastructure (bucket4j `ThrottleManagerImpl`) exists only in the `web3` module. The rest-java `NetworkController` has no rate-limiting filter, no `@RateLimiter`, and no request concurrency cap on `GET /api/v1/network/stake`. The endpoint is publicly accessible with no authentication.

**Exploit flow:**

1. A network partition occurs between the rest-java pod and the PostgreSQL instance (or an attacker induces one via firewall rule, BGP manipulation, etc.).
2. The attacker sends ≥10 concurrent `GET /api/v1/network/stake` requests (HikariCP default pool size is 10).
3. Each request acquires a JDBC connection and blocks indefinitely in `findLatest()`.
4. The pool is exhausted. All subsequent requests to **any** endpoint on the same rest-java instance wait up to HikariCP's `connectionTimeout` (default 30 s) and then fail with `SQLTimeoutException` / HTTP 500.
5. The service is effectively down for all users for the duration of the partition.

### Impact Explanation

Full REST API denial-of-service for the rest-java service. Because all endpoints share the same HikariCP pool, exhausting it via `/api/v1/network/stake` blocks `/api/v1/network/nodes`, `/api/v1/network/fees`, `/api/v1/accounts`, and every other endpoint. The attacker needs only 10 concurrent HTTP requests — trivially achievable with `curl`, `ab`, or any HTTP client — and no credentials.

### Likelihood Explanation

**Precondition:** A DB network partition must exist. This can arise from infrastructure failures (cloud provider networking issues, misconfigured security groups, rolling DB failover) or from an attacker with network-layer access (e.g., cloud tenant with ability to manipulate routing, or an insider). The attacker does not need to cause the partition themselves — they only need to detect it (e.g., by observing slow responses) and then flood the endpoint. The attack requires zero authentication, zero special knowledge of the system, and only ~10 HTTP requests. Repeatability is trivial.

### Recommendation

1. **Set a JDBC socket timeout on the runtime pool.** Add `socketTimeout=30` (seconds) to the PostgreSQL JDBC URL in the HikariCP configuration, or set `spring.datasource.hikari.connection-timeout` and ensure `spring.datasource.hikari.keepalive-time` / `spring.datasource.hikari.max-lifetime` are tuned. This bounds how long a JDBC thread can block on a dead socket.

2. **Add rate limiting to the rest-java network endpoints.** Apply a per-IP or global concurrency/rate limit (e.g., via a servlet filter using bucket4j, or at the ingress/API gateway layer) to `GET /api/v1/network/stake`.

3. **Consider caching the result.** Since `network_stake` data changes only once per staking period (~24 h), the result of `findLatest()` can be cached in-memory (e.g., with Spring `@Cacheable` and a short TTL), eliminating the DB round-trip for the vast majority of requests and making the endpoint immune to DB-layer DoS.

4. **Set `statement_timeout` via JDBC connection properties** (not just at the DB user level) so the driver-side timeout fires even when the server's cancellation cannot be delivered.

### Proof of Concept

```bash
# Step 1: Induce or wait for a DB network partition
# (e.g., block TCP port 5432 from the rest-java pod to the DB)

# Step 2: Send 15 concurrent requests to exhaust the pool (default size 10)
for i in $(seq 1 15); do
  curl -s http://<mirror-node-host>/api/v1/network/stake &
done
wait

# Step 3: Verify DoS — all other endpoints now return 500 or hang
curl -v http://<mirror-node-host>/api/v1/network/nodes
# Expected: connection pool timeout error / HTTP 500 after ~30s
```

During the partition, each of the 15 requests acquires (or waits for) a JDBC connection and blocks. Once the 10-connection pool is full, all other API calls fail until the partition resolves or the application is restarted.