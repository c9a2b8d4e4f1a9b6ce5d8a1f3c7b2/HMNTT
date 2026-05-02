### Title
Unauthenticated Cache-Busting DoS via Unbounded gRPC `subscribeTopic` Calls with Unique Topic IDs

### Summary
The `topicExists()` method in `TopicMessageServiceImpl` calls `entityRepository.findById()` on every `subscribeTopic()` invocation. While a Caffeine cache is present, it only protects against repeated calls with the **same** topicId — an attacker supplying a distinct topicId per request bypasses the cache entirely, forcing one database query per call. No rate limiting exists on the gRPC layer, and the per-connection concurrency cap is trivially bypassed by opening multiple connections.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicExists()` → `entityRepository.findById(topicId.getId())` [1](#0-0) 

The `@Cacheable` annotation on `EntityRepository.findById()` uses `unless = "#result == null"`: [2](#0-1) 

When a topicId does not exist in the database, `findById` returns `Optional.empty()`. Because `Optional.empty() != null`, the `unless` condition is **false**, so the empty result **is** cached. This means the cache only prevents repeated DB hits for the **same** topicId. An attacker who rotates through unique topicId values (the Hedera entity ID space is effectively unbounded: `shard.realm.num` with `num` as a `long`) forces one DB query per unique ID, indefinitely.

**No rate limiting exists on the gRPC endpoint.** The throttling infrastructure (`ThrottleConfiguration`, `ThrottleManagerImpl`) is scoped exclusively to the `web3` module: [3](#0-2) 

The only concurrency control in the gRPC module is `maxConcurrentCallsPerConnection = 5`: [4](#0-3) 

This is a **per-connection** limit. An attacker opens N connections and achieves 5N concurrent `subscribeTopic` calls, each with a fresh topicId, each hitting the database.

When `checkTopicExists = true` (the default): [5](#0-4) 

the call fails fast with `EntityNotFoundException`, so the attacker's connection is recycled immediately and can be reused for the next request, maximizing query throughput.

The entity cache has a maximum size of 50,000 entries with a 24-hour TTL: [6](#0-5) 

An attacker using more than 50,000 unique topicIds causes LRU eviction, preventing the cache from ever serving a hit and sustaining continuous DB pressure.

### Impact Explanation
Each attacker-controlled `subscribeTopic` call with a unique topicId issues a `SELECT` against the `entity` table. With no rate limiting, a single attacker with modest bandwidth can sustain thousands of DB queries per second, exhausting database connection pools, increasing query latency for legitimate users, and potentially causing full service unavailability. The gRPC service is publicly exposed and requires no authentication or credentials to call.

### Likelihood Explanation
The attack requires no privileges, no valid topic IDs, and no special tooling — a standard gRPC client (e.g., `grpcurl`, any HCS SDK) suffices. The attacker simply increments the topic number field in each `ConsensusTopicQuery`. The fast-fail path (entity not found → stream error) means connections are recycled rapidly, maximizing request rate. This is repeatable, automatable, and requires no sustained state.

### Recommendation
1. **Add rate limiting to the gRPC layer** — implement a per-IP or global token-bucket limiter (analogous to `ThrottleConfiguration` in the `web3` module) applied in `ConsensusController` or via a gRPC server interceptor before `subscribeTopic` is invoked.
2. **Cache negative lookups explicitly** — the current `unless = "#result == null"` already caches `Optional.empty()`, which is correct, but the cache is only effective for repeated same-topicId calls. Consider also validating topicId ranges (e.g., reject IDs above a known maximum entity num) before hitting the DB.
3. **Enforce a global concurrent-subscriber cap** — the existing `subscriberCount` metric is tracked but never enforced as a hard limit; add a check that rejects new subscriptions when the count exceeds a configurable threshold.

### Proof of Concept
```python
import grpc
from hedera import consensus_service_pb2, consensus_service_pb2_grpc, basic_types_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

# Rotate through unique, non-existent topic IDs to bypass cache
for topic_num in range(1_000_000, 2_000_000):
    topic_id = basic_types_pb2.TopicID(shardNum=0, realmNum=0, topicNum=topic_num)
    query = consensus_service_pb2.ConsensusTopicQuery(topicID=topic_id)
    try:
        # Each call triggers entityRepository.findById() → DB query
        # Fails fast with NOT_FOUND, connection recycled immediately
        for _ in stub.subscribeTopic(query):
            break
    except grpc.RpcError:
        pass  # Expected; move to next unique topicId
```

Each iteration issues one `SELECT` to the `entity` table with no rate limiting. Running this in parallel across multiple threads/connections multiplies the DB load linearly.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L14-15)
```java
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** web3/src/main/java/org/hiero/mirror/web3/config/ThrottleConfiguration.java (L14-55)
```java
@Configuration(proxyBeanMethods = false)
@RequiredArgsConstructor
public class ThrottleConfiguration {

    public static final String GAS_LIMIT_BUCKET = "gasLimitBucket";
    public static final String RATE_LIMIT_BUCKET = "rateLimitBucket";
    public static final String OPCODE_RATE_LIMIT_BUCKET = "opcodeRateLimitBucket";

    private final ThrottleProperties throttleProperties;

    @Bean(name = RATE_LIMIT_BUCKET)
    Bucket rateLimitBucket() {
        long rateLimit = throttleProperties.getRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }

    @Bean(name = GAS_LIMIT_BUCKET)
    Bucket gasLimitBucket() {
        long gasLimit = throttleProperties.getGasPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(gasLimit)
                .refillGreedy(gasLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder()
                .withSynchronizationStrategy(SynchronizationStrategy.SYNCHRONIZED)
                .addLimit(limit)
                .build();
    }

    @Bean(name = OPCODE_RATE_LIMIT_BUCKET)
    Bucket opcodeRateLimitBucket() {
        long rateLimit = throttleProperties.getOpcodeRequestsPerSecond();
        final var limit = Bandwidth.builder()
                .capacity(rateLimit)
                .refillGreedy(rateLimit, Duration.ofSeconds(1))
                .build();
        return Bucket.builder().addLimit(limit).build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/CacheConfiguration.java (L47-54)
```java
    @Bean(ENTITY_CACHE)
    @Primary
    CacheManager entityCache(GrpcProperties grpcProperties) {
        int cacheSize = grpcProperties.getEntityCacheSize();
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification("recordStats,expireAfterWrite=24h,maximumSize=" + cacheSize);
        return caffeineCacheManager;
```
