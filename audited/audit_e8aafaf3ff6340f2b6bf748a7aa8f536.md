### Title
Unauthenticated GraphQL `getByIdAndType()` Path Lacks Rate Limiting, Enabling Database Exhaustion via Sequential Entity ID Enumeration

### Summary
The `getByIdAndType()` method in `EntityServiceImpl.java` calls `entityRepository.findById()` on every invocation with no application-level rate limiting and no result caching in the GraphQL module's `EntityRepository`. An unprivileged attacker can flood the `/graphql/alpha` endpoint with sequential entity ID queries, causing every request to hit the database, exhausting the connection pool and degrading response times for all users.

### Finding Description
**Exact code path:**

`AccountController.account()` → `entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)` → `entityRepository.findById(entityId.getId())` [1](#0-0) 

The graphql module's `EntityRepository` inherits `findById()` from Spring's `CrudRepository` with **no `@Cacheable` annotation**: [2](#0-1) 

Contrast this with the `grpc` module's `EntityRepository`, which annotates `findById()` with `@Cacheable`: [3](#0-2) 

The GraphQL module contains **zero application-level rate limiting code** — no `ThrottleManager`, no `Bucket4j`, no `@RateLimiting`. The `grep` search for any throttle/rate-limit construct in `graphql/**/*.java` returns no matches.

**Why existing checks fail:**

1. **Traefik `inFlightReq: amount: 5` per IP** — limits *concurrent* in-flight requests per source IP, not *request rate*. An attacker sending requests sequentially (one after another) is never blocked; 5 concurrent connections × thousands of sequential requests/second still saturates the DB. [4](#0-3) 

2. **GCP `maxRatePerEndpoint: 250`** — this is a *global* rate across all pods, not per-client. The comment explicitly notes it "Requires a change to HPA to take effect," meaning it is not reliably enforced. It also does not block a single attacker from consuming the entire budget. [5](#0-4) 

3. **`MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`** — these guard against deeply nested or complex queries, not high-frequency simple queries. A single-field `account(input:{entityId:"0.0.N"})` query has complexity 1 and depth 1. [6](#0-5) 

4. **`global.middleware: false`** — the global middleware chain is disabled, so no shared rate-limiting middleware applies. [7](#0-6) 

### Impact Explanation
Each unique entity ID submitted to `getByIdAndType()` causes an uncached `SELECT * FROM entity WHERE id = ?` query. With thousands of requests per second using sequential IDs (0.0.1, 0.0.2, …), the HikariCP connection pool is saturated. The Prometheus alert `GraphQLHighDBConnections` fires at 75% utilization, confirming the DB connection pool is a recognized bottleneck. Legitimate users experience timeouts and degraded latency. This is a griefing/DoS with no economic cost to the attacker. [8](#0-7) 

### Likelihood Explanation
No authentication is required. The endpoint `/graphql/alpha` is publicly reachable. The attack requires only an HTTP client capable of sending POST requests. Sequential entity IDs are trivially enumerable (Hedera entity IDs are sequential integers in `shard.realm.num` format). A single machine with a persistent connection can bypass the `inFlightReq` concurrency limit by pipelining requests. The attack is repeatable indefinitely.

### Recommendation
1. **Add application-level per-IP rate limiting** in the GraphQL module using Bucket4j (already a dependency in `web3`), mirroring `ThrottleConfiguration` / `ThrottleManagerImpl`.
2. **Add `@Cacheable`** to `findById()` in the graphql module's `EntityRepository`, consistent with the `grpc` module's pattern.
3. **Enforce per-client rate limiting at the ingress layer** (e.g., Traefik `rateLimit` middleware with `average` and `burst` per source IP), not just concurrency limiting via `inFlightReq`.
4. Consider enforcing the GCP `maxRatePerEndpoint` properly by coupling it with HPA configuration.

### Proof of Concept
```bash
# Send 10,000 sequential entity ID queries with no authentication
for i in $(seq 1 10000); do
  curl -s -X POST https://<mirror-node>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ account(input:{entityId:\\\"0.0.$i\\\"}) { id } }\"}" &
done
# Each request triggers: SELECT * FROM entity WHERE id = <i>
# DB connection pool saturates; legitimate queries time out
```
No credentials, API keys, or special privileges are required.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L12-17)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** charts/hedera-mirror-graphql/values.yaml (L56-56)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```

**File:** charts/hedera-mirror-graphql/values.yaml (L89-89)
```yaml
  middleware: false
```

**File:** charts/hedera-mirror-graphql/values.yaml (L138-142)
```yaml
  - inFlightReq:
      amount: 5
      sourceCriterion:
        ipStrategy:
          depth: 1
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L43-45)
```java
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);
```
