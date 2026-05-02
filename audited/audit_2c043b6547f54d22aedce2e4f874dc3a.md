### Title
GraphQL evmAddress Query Flood Exhausts HikariCP Connection Pool During Network Partition (DoS)

### Summary
The `getByEvmAddressAndType()` method in `EntityServiceImpl` issues a blocking JDBC query against `EntityRepository` for every valid evmAddress request with no application-level rate limiting. During a network partition, each query holds a HikariCP connection open until the driver timeout expires. An unprivileged attacker sending concurrent requests from multiple source IPs can exhaust the entire connection pool, denying service to all legitimate users.

### Finding Description

**Exact code path:**

`AccountController.account()` (line 51-54) passes the evmAddress to `EntityServiceImpl.getByEvmAddressAndType()` (lines 34-41), which unconditionally calls either `entityRepository.findById()` or `entityRepository.findByEvmAddress()` — both are synchronous, blocking JDBC calls backed by HikariCP. [1](#0-0) 

`EntityRepository.findByEvmAddress()` executes a native SQL query: [2](#0-1) 

**Root cause — failed assumption:** The design assumes the database is always reachable within a short window. During a network partition, each JDBC call blocks for the full HikariCP `connectionTimeout` (Spring Boot default: 30 seconds) before throwing. Every concurrent request holds one pool connection for the entire duration of that timeout. HikariCP's default `maximumPoolSize` is 10. There is no application-level rate limiter in the GraphQL module — unlike the web3 module which has `ThrottleConfiguration` with bucket4j: [3](#0-2) 

No equivalent exists anywhere under `graphql/src/main/java/`.

**Why the existing infrastructure check is insufficient:**

The only relevant mitigation is the Traefik `inFlightReq` middleware configured at `amount: 5` per source IP: [4](#0-3) 

This is bypassable in two ways:
1. An attacker using just **2 source IPs** sends 5 concurrent requests each → 10 simultaneous DB connections → pool fully exhausted.
2. The `ipStrategy.depth: 1` reads the first IP from `X-Forwarded-For`, which can be spoofed if the load balancer does not strip/override that header.

Additionally, the `retry` middleware (3 attempts, 100ms interval) is configured alongside `inFlightReq`: [5](#0-4) 

During a partition, retries multiply connection-hold time by up to 3×, worsening exhaustion.

The GraphQL schema `@Pattern` constraint on `evmAddress` only validates format (40 hex chars): [6](#0-5) 

This does not prevent high-volume valid-format requests from reaching the repository layer.

### Impact Explanation
When the HikariCP pool is exhausted, all subsequent GraphQL requests that require a DB connection (every query) receive a `SQLTimeoutException` or are queued indefinitely. This is a **full availability outage** for the GraphQL endpoint. The `GraphQLHighDBConnections` Prometheus alert only fires after 5 minutes at >75% utilization — well after the outage has begun: [7](#0-6) 

Severity: **High** — complete denial of service to all users, not just the attacker.

### Likelihood Explanation
- **Precondition:** A network partition between the GraphQL pod and the PostgreSQL database (e.g., a misconfigured network policy, a DB failover, or a deliberate partition). This is a realistic operational event.
- **Attacker capability:** Zero privileges required. Only valid 40-hex-char evmAddress strings are needed, which are trivially generated. Two IPs suffice to bypass the per-IP `inFlightReq` limit.
- **Repeatability:** The attack is fully repeatable and can be sustained for the duration of the partition. The attacker does not need to know a partition is occurring — they can continuously flood the endpoint and the attack becomes effective the moment a partition starts.

### Recommendation

1. **Add application-level rate limiting to the GraphQL module** using bucket4j (already a dependency in web3), mirroring `ThrottleConfiguration`, applied as a Spring `WebFilter` or `HandlerInterceptor` before the GraphQL execution layer.
2. **Set an explicit, short HikariCP `connectionTimeout`** (e.g., 2–5 seconds) and `maximumPoolSize` in the GraphQL application configuration so connections fail fast during a partition rather than holding for 30 seconds.
3. **Set a JDBC `socketTimeout`** on the PostgreSQL driver (e.g., `socketTimeout=5`) so in-flight queries are aborted promptly during a partition.
4. **Do not rely solely on per-IP `inFlightReq`** for DoS protection; enforce a global concurrent-request cap at the application level.

### Proof of Concept

```
# Simulate network partition (on the DB host or via iptables):
# iptables -A OUTPUT -p tcp --dport 5432 -j DROP

# From attacker IP 1 — 5 concurrent requests (saturates per-IP limit):
for i in $(seq 1 5); do
  curl -s -X POST https://<graphql-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input: { evmAddress: \"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\" }) { id } }"}' &
done

# From attacker IP 2 — 5 more concurrent requests:
# (repeat above from a second IP or with spoofed X-Forwarded-For)

# Result: all 10 HikariCP connections are held open for up to 30s each.
# Legitimate requests from any IP now receive connection pool timeout errors.
# Repeat in a loop to sustain the outage for the partition duration.
```

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L34-41)
```java
    public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
        byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
        var buffer = ByteBuffer.wrap(evmAddressBytes);
        if (buffer.getInt() == 0 && buffer.getLong() == 0) {
            return entityRepository.findById(buffer.getLong()).filter(e -> e.getType() == type);
        }
        return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L16-17)
```java
    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L24-32)
```java
    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
```

**File:** charts/hedera-mirror-graphql/values.yaml (L143-145)
```yaml
  - retry:
      attempts: 3
      initialInterval: 100ms
```

**File:** charts/hedera-mirror-graphql/values.yaml (L204-214)
```yaml
  GraphQLHighDBConnections:
    annotations:
      description: "{{ $labels.namespace }}/{{ $labels.pod }} is using {{ $value | humanizePercentage }} of available database connections"
      summary: "Mirror GraphQL API database connection utilization exceeds 75%"
    enabled: true
    expr: sum(hikaricp_connections_active{application="graphql"}) by (namespace, pod) / sum(hikaricp_connections_max{application="graphql"}) by (namespace, pod) > 0.75
    for: 5m
    labels:
      application: graphql
      area: resource
      severity: critical
```

**File:** graphql/src/main/resources/graphql/account.graphqls (L96-96)
```text
    evmAddress: String @Pattern(regexp: "^(0x)?[a-fA-F0-9]{40}$")
```
