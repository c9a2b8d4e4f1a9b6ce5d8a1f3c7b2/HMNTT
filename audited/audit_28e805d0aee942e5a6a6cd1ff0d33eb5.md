### Title
Unauthenticated GraphQL Endpoint Allows Unbounded DB Miss Queries via Valid Non-Existent EntityId Values

### Summary
The GraphQL module's `getByIdAndType()` method issues an uncached `entityRepository.findById()` database query for every request, with no rate limiting on the `/graphql/alpha` endpoint. An unprivileged attacker can send a high volume of requests supplying valid-but-non-existent `EntityIdInput` values (any combination within the accepted shard/realm/num ranges), causing a flood of DB primary-key miss queries that exhaust the HikariCP connection pool and elevate DB CPU well above the 30% baseline threshold.

### Finding Description

**Exact code path:**

`AccountController.account()` receives an unauthenticated POST to `/graphql/alpha`, extracts `entityId` from `AccountInput`, and calls:

```java
// AccountController.java line 43
entityService.getByIdAndType(toEntityId(entityId), EntityType.ACCOUNT)
```

`toEntityId()` calls `EntityId.of(entityId.getShard(), entityId.getRealm(), entityId.getNum())` with no upper-bound check beyond the encoding mask. [1](#0-0) 

`getByIdAndType()` then unconditionally issues a DB query:

```java
// EntityServiceImpl.java line 25
return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
``` [2](#0-1) 

There is no caching of the DB result at the service layer. The `EntityId` Caffeine cache only caches the Java `EntityId` object itself, not the repository query result. [3](#0-2) 

**Root cause — failed assumption:** The schema only enforces `@Min(value: 0)` on `shard`, `realm`, and `num` — no `@Max` constraint. Any value within the encoding range (shard 0–1023, realm 0–65535, num 0–274877906943) is accepted and forwarded to the DB. [4](#0-3) 

`EntityId.encode()` validates the upper bounds and throws `InvalidEntityException` only for values that exceed the mask — values at or below the mask (including the maximum) are valid and reach the DB. [5](#0-4) 

**No rate limiting in the GraphQL module:** `GraphQlConfiguration` only configures per-query complexity (max 200) and depth (max 10) instrumentation, plus parser token limits. There is no requests-per-second throttle. [6](#0-5) 

By contrast, the `web3` module has a full `ThrottleManagerImpl` with bucket4j rate limiting — this protection is entirely absent from the GraphQL module. [7](#0-6) 

### Impact Explanation

Each request with a valid but non-existent EntityId causes one DB primary-key lookup that returns empty. With no rate limiting, an attacker can sustain thousands of such requests per second. The HikariCP connection pool (monitored via `hikaricp_connections_active`) becomes saturated, legitimate queries queue or time out, and DB CPU rises proportionally. The existing Prometheus alert for `GraphQLHighDBConnections` (threshold 75%) confirms this is a recognized risk surface — but there is no preventive control in the code path. [8](#0-7) 

### Likelihood Explanation

No authentication, API key, or credential is required to reach `/graphql/alpha`. The attacker only needs to know the GraphQL schema (publicly documented) and send standard HTTP POST requests. The attack is trivially scriptable with `curl` or any HTTP client, is repeatable indefinitely, and requires no special knowledge beyond the valid EntityId encoding ranges. A single machine with a moderate network connection is sufficient to saturate the DB connection pool.

### Recommendation

1. **Add rate limiting to the GraphQL module** — mirror the `ThrottleManagerImpl`/`ThrottleConfiguration` pattern from the `web3` module, implementing a `WebGraphQlInterceptor` that enforces a configurable requests-per-second limit per IP or globally.
2. **Add result caching in `EntityServiceImpl.getByIdAndType()`** — cache `Optional<Entity>` results (including empty results for misses) with a short TTL (e.g., 1–5 seconds) using Caffeine or Spring Cache, so repeated lookups for the same non-existent ID do not hit the DB.
3. **Add `@Max` constraints to `EntityIdInput`** — restrict `shard`, `realm`, and `num` to the actual network-deployed maximums (e.g., shard ≤ 0, realm ≤ 0, num ≤ a configured maximum) to reduce the valid attack surface.

### Proof of Concept

```bash
# Send 10,000 requests with a valid but non-existent EntityId (max values)
# No authentication required
for i in $(seq 1 10000); do
  curl -s -X POST https://<mirror-node-host>/graphql/alpha \
    -H 'Content-Type: application/json' \
    -d '{"query":"{ account(input: { entityId: { shard: 0, realm: 0, num: 274877906942 } }) { id } }"}' &
done
wait
```

Each request passes schema validation (`num: 274877906942` is below the 274877906943 mask limit), passes `EntityId.encode()`, and triggers `entityRepository.findById()` with a DB miss. With no rate limiting, all 10,000 requests are processed concurrently, exhausting the HikariCP connection pool and spiking DB CPU above the 30% baseline.

### Citations

**File:** graphql/src/main/java/org/hiero/mirror/graphql/util/GraphQlUtils.java (L64-66)
```java
    public static EntityId toEntityId(EntityIdInput entityId) {
        return EntityId.of(entityId.getShard(), entityId.getRealm(), entityId.getNum());
    }
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/service/EntityServiceImpl.java (L24-26)
```java
    public Optional<Entity> getByIdAndType(EntityId entityId, EntityType type) {
        return entityRepository.findById(entityId.getId()).filter(e -> e.getType() == type);
    }
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L42-48)
```java
    private static final String CACHE_DEFAULT = "expireAfterAccess=60m,maximumSize=500000,recordStats";
    private static final String CACHE_PROPERTY = "HIERO_MIRROR_COMMON_CACHE_ENTITYID";
    private static final String CACHE_SPEC = System.getProperty(CACHE_PROPERTY, CACHE_DEFAULT);
    private static final Cache<Long, EntityId> CACHE = Caffeine.from(CACHE_SPEC).build();

    private static final Comparator<EntityId> COMPARATOR =
            Comparator.nullsFirst(Comparator.comparingLong(EntityId::getId));
```

**File:** common/src/main/java/org/hiero/mirror/common/domain/entity/EntityId.java (L75-85)
```java
    private static long encode(long shard, long realm, long num) {
        if (shard > SHARD_MASK || shard < 0 || realm > REALM_MASK || realm < 0 || num > NUM_MASK || num < 0) {
            throw new InvalidEntityException("Invalid entity ID: " + shard + "." + realm + "." + num);
        }

        if (shard == 0 && realm == 0) {
            return num;
        }

        return (num & NUM_MASK) | (realm & REALM_MASK) << NUM_BITS | (shard & SHARD_MASK) << (REALM_BITS + NUM_BITS);
    }
```

**File:** graphql/src/main/resources/graphql/common.graphqls (L169-178)
```text
input EntityIdInput {
    "The shard number to allow for horizontal scaling of networks. Defaults to zero."
    shard: Long! = 0 @Min(value: 0)

    "The realm number. Defaults to zero."
    realm: Long! = 0 @Min(value: 0)

    "The unique incrementing identifier associated with this entity."
    num: Long! @Min(value: 0)
}
```

**File:** graphql/src/main/java/org/hiero/mirror/graphql/config/GraphQlConfiguration.java (L41-49)
```java
    @Bean
    GraphQlSourceBuilderCustomizer graphQlCustomizer(PreparsedDocumentProvider provider) {
        var maxQueryComplexity = new MaxQueryComplexityInstrumentation(200);
        var maxQueryDepth = new MaxQueryDepthInstrumentation(10);
        var instrumentation = new ChainedInstrumentation(maxQueryComplexity, maxQueryDepth);

        return b -> b.configureGraphQl(
                graphQL -> graphQL.instrumentation(instrumentation).preparsedDocumentProvider(provider));
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
