### Title
Unbounded Redis Channel Subscription Growth via Unauthenticated Topic Subscription Flooding

### Summary
`RedisTopicListener.getSharedListener` uses an unbounded `ConcurrentHashMap` (`topicMessages`) keyed by topic name, and each distinct topic ID causes a new Redis channel subscription to be registered with `ReactiveRedisMessageListenerContainer`. There is no cap on the number of distinct topic subscriptions, no global connection limit, and the gRPC endpoint requires no authentication. An attacker who opens many connections and subscribes to many distinct existing topic IDs can exhaust Redis pub/sub resources and degrade message delivery for all legitimate subscribers.

### Finding Description

**Code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java`

- Line 33/43: `topicMessages` is a plain `ConcurrentHashMap<String, Flux<TopicMessage>>` with no size bound.
- Line 61 (`getSharedListener`): `topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic))` — every distinct topic key that is not already present triggers a new Redis channel subscription.
- Lines 68–80 (`subscribe`): calls `r.receive(Collections.singletonList(topic), ...)` on the shared `ReactiveRedisMessageListenerContainer`, registering a new pub/sub channel with Redis, then wraps it with `.share()`.
- Lines 82–85 (`unsubscribe`): the entry is only removed when the last subscriber cancels or the flux completes.

**Root cause:** The design assumes the number of concurrently subscribed distinct topic IDs is small and bounded by legitimate usage. There is no maximum-size enforcement on `topicMessages` and no global cap on the number of Redis channel subscriptions the container may hold.

**Exploit flow:**

1. `TopicMessageServiceImpl.subscribeTopic` (line 87–91) gates the listener call behind `topicExists(filter).thenMany(...)`. With the default `checkTopicExists=true`, only existing topic IDs pass this check. Existing topic IDs on Hedera are publicly enumerable via the REST API (`/api/v1/topics`), so the attacker enumerates them.
2. The attacker opens a large number of TCP connections to the unauthenticated gRPC port (default 5600). There is no global connection limit in the codebase.
3. `NettyProperties.maxConcurrentCallsPerConnection` defaults to 5 (docs line 424), limiting concurrent streams *per connection*, not globally. With N connections the attacker holds N×5 concurrent `subscribeTopic` streams.
4. Each stream targets a different existing topic ID, causing `computeIfAbsent` to insert a new entry and `ReactiveRedisMessageListenerContainer.receive(...)` to register a new Redis pub/sub channel.
5. The `topicMessages` map and the Redis channel subscription set grow proportionally to the number of attacker-controlled connections × 5, with no server-side ceiling.

**Why existing checks are insufficient:**

- `checkTopicExists=true`: Prevents subscribing to non-existent topics, but existing topics are publicly enumerable; this is not a meaningful barrier.
- `maxConcurrentCallsPerConnection=5`: Per-connection limit only; does not bound total subscriptions across many connections.
- `.share()` / `unsubscribe`: Entries are cleaned up only when the attacker voluntarily disconnects; while connections are held open the map and Redis subscriptions remain.
- No authentication, no rate limiting, no per-IP connection limit is present in the gRPC layer.

### Impact Explanation

Redis pub/sub performance degrades as the number of subscribed channels grows. With thousands of active channel subscriptions, the `ReactiveRedisMessageListenerContainer` must route every published message through an increasingly large subscription set, increasing CPU and memory pressure on both the mirror node JVM and the Redis server. Under sufficient load this causes message delivery latency to spike and eventually message drops (backpressure overflow via `onBackpressureBuffer` in `SharedTopicListener` line 24), directly causing missing records for legitimate subscribers — the exact failure mode described in the scope.

### Likelihood Explanation

The gRPC port is publicly accessible with no authentication. Existing topic IDs are trivially enumerable via the public REST API. Opening thousands of long-lived gRPC streams requires only a standard gRPC client library and modest network resources. The attack is repeatable and can be sustained indefinitely as long as the attacker holds connections open. No privileged access, credentials, or on-chain transactions are required.

### Recommendation

1. **Cap the `topicMessages` map**: Replace `ConcurrentHashMap` with a bounded structure (e.g., Caffeine cache with a maximum size and eviction policy) so that the number of simultaneously tracked Redis channel subscriptions is bounded regardless of client behavior.
2. **Global concurrent-subscription limit**: Add a server-wide `AtomicLong` counter (similar to `subscriberCount` in `TopicMessageServiceImpl`) that rejects new subscriptions above a configurable threshold.
3. **Per-IP / per-connection rate limiting**: Enforce a maximum number of concurrent streams per source IP at the Netty/gRPC interceptor layer, not just per-connection.
4. **Connection limit**: Configure `maxConnectionAge` and a global connection count ceiling in `NettyProperties` to bound total open connections.

### Proof of Concept

```python
# Pseudocode – requires grpcio and the mirror node proto stubs
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

# Step 1: enumerate existing topic IDs from the public REST API
import requests
topics = [t["topic_id"] for t in
          requests.get("https://<mirror>/api/v1/topics?limit=1000").json()["topics"]]

# Step 2: open many connections, each subscribing to a different topic
def flood(topic_num):
    channel = grpc.insecure_channel("<mirror>:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery()
    req.topicID.topicNum = topic_num
    for _ in stub.subscribeTopic(req):   # blocks, keeping Redis subscription alive
        pass

threads = [threading.Thread(target=flood, args=(t,)) for t in topics[:5000]]
for t in threads:
    t.start()
# Result: 5000 entries in topicMessages, 5000 Redis pub/sub channels registered,
# Redis and JVM resources exhausted, legitimate subscribers experience message loss.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-80)
```java
    private Flux<TopicMessage> subscribe(Topic topic) {
        Duration interval = listenerProperties.getInterval();

        return container
                .flatMapMany(r -> r.receive(Collections.singletonList(topic), channelSerializer, messageSerializer))
                .map(Message::getMessage)
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
                .doOnError(t -> log.error("Error listening for messages", t))
                .doOnSubscribe(s -> log.info("Creating shared subscription to {}", topic))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L82-85)
```java
    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L22-25)
```java
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```
