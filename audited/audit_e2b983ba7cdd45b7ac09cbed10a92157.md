### Title
Unbounded Concurrent Subscriptions Enable Per-Subscriber Buffer Heap Exhaustion via Zero-Demand gRPC Clients

### Summary
`SharedTopicListener.listen()` allocates a per-subscriber `onBackpressureBuffer` of up to 16,384 `TopicMessage` objects for every caller. Because there is no limit on concurrent subscriptions, no authentication, and no connection throttling, an unauthenticated attacker can open arbitrarily many gRPC connections, subscribe to topics, and never request items, causing each subscription to accumulate up to 16,384 buffered messages in JVM heap simultaneously. Across enough concurrent connections this exhausts heap memory on the targeted node.

### Finding Description

**Code path:**

`SharedTopicListener.listen()` — [1](#0-0) 

```java
public Flux<TopicMessage> listen(TopicMessageFilter filter) {
    return getSharedListener(filter)
            .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
            .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
            .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
}
```

`maxBufferSize` defaults to 16,384 and is bounded only between 8,192 and 65,536: [2](#0-1) 

`RedisTopicListener.subscribe()` uses `.share()` so the upstream Redis connection is shared, but `onBackpressureBuffer` is applied **after** the shared source, inside `listen()`, meaning **each subscriber receives its own independent buffer**: [3](#0-2) 

**Root cause:** The buffer operator is placed per-subscriber in the `listen()` pipeline, not on the shared upstream. There is no cap on concurrent subscriptions, no authentication, and no rate limiting anywhere in the gRPC service layer. [4](#0-3)  (`subscriberCount` is a metrics gauge only — it enforces nothing.)

**Why `BufferOverflowStrategy.ERROR` is insufficient:** When the buffer fills to 16,384 items the subscription is terminated with an error. This bounds memory *per subscription lifetime*, but does not prevent the attacker from:
1. Holding N concurrent subscriptions simultaneously, each accumulating messages up to the limit before erroring.
2. Immediately re-subscribing after each error, keeping N buffers live at all times.

The attacker controls the concurrency level N with no server-side constraint.

### Impact Explanation

Each `TopicMessage` carries consensus timestamp, topic ID, sequence number, message bytes, and running hash — conservatively ~500–2,000 bytes on heap. With N=1,000 concurrent zero-demand subscribers:

- Lower bound: 1,000 × 16,384 × 500 B ≈ **8 GB**
- Upper bound: 1,000 × 16,384 × 2,000 B ≈ **32 GB**

A typical JVM heap for a mirror-node gRPC process is 2–8 GB. Exhausting it causes `OutOfMemoryError`, crashing the process. Repeating this against multiple nodes simultaneously can take down 30%+ of the mirror-node fleet, matching the stated severity scope. No privileged access is required.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly reachable (no authentication found in the codebase). A single attacker machine can open thousands of gRPC streaming connections using any standard gRPC client library. The attack is fully scriptable, repeatable, and requires no knowledge of internal state — only a valid (or even non-existent, if `checkTopicExists=false`) topic ID. [5](#0-4) 

### Recommendation

1. **Enforce a per-IP and global concurrent-subscription limit** in a gRPC server interceptor before the subscription reaches `listen()`.
2. **Move `onBackpressureBuffer` to the shared upstream** (inside `subscribe()`, before `.share()`) so the buffer is shared across all subscribers to a topic rather than duplicated per subscriber.
3. **Add authentication/authorization** to the gRPC endpoint so anonymous callers cannot open unlimited streams.
4. **Configure Netty connection limits** via `NettyProperties` (max connections, max streams per connection). [6](#0-5) 

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

TARGET = "mirror-node-grpc:5600"
NUM_CONNECTIONS = 2000

def zero_demand_subscribe():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,  # any valid topic ID
    )
    # Open stream but never iterate — zero demand
    stream = stub.subscribeTopic(req)
    # Block forever without consuming
    import time; time.sleep(3600)

threads = [threading.Thread(target=zero_demand_subscribe) for _ in range(NUM_CONNECTIONS)]
for t in threads: t.start()
for t in threads: t.join()
```

**Expected result:** Each of the 2,000 connections causes the server to allocate a 16,384-slot `onBackpressureBuffer`. As the topic receives messages, each buffer fills independently. Aggregate heap consumption reaches multiple gigabytes, triggering `OutOfMemoryError` on the targeted node.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L21-23)
```java
    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L1-1)
```java
// SPDX-License-Identifier: Apache-2.0
```
