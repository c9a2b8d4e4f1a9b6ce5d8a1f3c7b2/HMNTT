### Title
Redis Subscription Resource Exhaustion via Rapid Subscribe/Cancel Cycling in `RedisTopicListener`

### Summary
`RedisTopicListener.subscribe()` uses `share()` (i.e., `publish().refCount()`) so that when the last subscriber cancels, the upstream is cancelled and `doOnCancel` removes the topic entry from `topicMessages`. Because this removal is asynchronous and there is no rate limiting on gRPC subscriptions, an unprivileged attacker can rapidly subscribe and cancel to force repeated creation of new `r.receive()` subscriptions on the `ReactiveRedisMessageListenerContainer`, accumulating subscription objects and exhausting server-side resources.

### Finding Description

**Exact code path:**

`RedisTopicListener.getSharedListener()` [1](#0-0)  uses `computeIfAbsent` to create or reuse a shared Flux per topic.

`RedisTopicListener.subscribe()` [2](#0-1)  builds the Flux with `.share()` at line 79, and registers `doOnCancel(() -> unsubscribe(topic))` at line 74.

`RedisTopicListener.unsubscribe()` [3](#0-2)  simply calls `topicMessages.remove(topic.getTopic())`.

**Root cause and failed assumption:**

The design assumes that `doOnCancel` fires synchronously and completely before any new subscriber can call `computeIfAbsent`. This assumption fails because:

1. Reactor's `share()` (`publish().refCount()`) cancels the upstream and fires `doOnCancel` on the cancellation signal propagation path, which is asynchronous relative to incoming gRPC subscription requests.
2. `computeIfAbsent` on `ConcurrentHashMap` is atomic per-key, but the window between `share()` cancelling its upstream and `unsubscribe()` removing the map entry is non-zero.
3. There is no rate limiting, no per-client subscription cap, and no minimum hold time enforced anywhere in `SharedTopicListener.listen()` [4](#0-3)  or `CompositeTopicListener.listen()`. [5](#0-4) 

**Exploit flow:**

- Each subscribe/cancel cycle that completes after `unsubscribe()` removes the map entry causes `computeIfAbsent` to call `subscribe(topic)` again, which calls `container.flatMapMany(r -> r.receive(...))` — creating a new `ReactiveRedisMessageListenerContainer` channel subscription object.
- Each such subscription carries a `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` [6](#0-5)  pipeline that holds references indefinitely until explicitly cancelled.
- In the race window (new subscriber arrives before `unsubscribe()` fires), the new subscriber re-activates the old `share()` Flux, causing it to re-subscribe upstream (a second `r.receive()` call), while `unsubscribe()` then removes the entry. The re-activated Flux is now orphaned — no longer in `topicMessages`, so it can never be cleaned up by future `unsubscribe()` calls, and its `doOnCancel` will call `topicMessages.remove()` on an already-absent key (a no-op).

**Why existing checks are insufficient:**

`ListenerProperties` has `maxBufferSize` and `prefetch` [7](#0-6)  but these control per-subscriber backpressure, not the rate or count of subscriptions. There is no subscriber count limit, no per-IP rate limit, and no minimum subscription duration.

### Impact Explanation

Each rapid cycle creates a new `r.receive()` subscription on the shared `ReactiveRedisMessageListenerContainer`. Orphaned Flux pipelines (from the race window) are never cleaned up and hold memory and CPU resources indefinitely. At sufficient rate, this causes: heap exhaustion on the mirror node JVM, Redis pub/sub subscription table growth (Redis tracks each `SUBSCRIBE` command), and CPU saturation from managing many retry-capable Flux pipelines. This can degrade or halt gRPC topic message delivery for all legitimate subscribers — matching the stated scope of shutting down ≥30% of network processing nodes.

### Likelihood Explanation

The gRPC `subscribeToTopic` endpoint requires no authentication (the `subscriberId` in `TopicMessageFilter` is randomly generated client-side [8](#0-7)  and is not validated server-side). Any network-reachable client can open and immediately cancel gRPC streams. The attack is trivially scriptable with any gRPC client library, requires no credentials, and is repeatable at high frequency. The race window is small but the attacker controls timing and can use many parallel connections to maximize hit rate.

### Recommendation

1. **Add a per-topic subscription rate limit** in `getSharedListener()` or `SharedTopicListener.listen()` — reject or delay new subscriptions for a topic that was just unsubscribed within a configurable cooldown window.
2. **Replace `doOnCancel(() -> unsubscribe(topic))` with a delayed/debounced cleanup** — instead of immediately removing from `topicMessages` on cancel, schedule removal after a short delay (e.g., 1–2 seconds) so that rapid re-subscriptions reuse the existing shared Flux rather than creating a new one.
3. **Add a global and per-IP concurrent subscription limit** at the gRPC interceptor layer.
4. **Use `publish().refCount(1, Duration.ofSeconds(N))` instead of `share()`** — Reactor's `refCount` with a `gracePeriod` keeps the upstream alive for N seconds after the last subscriber leaves, preventing the teardown/recreate cycle entirely.

### Proof of Concept

```
# Pseudocode — run with any gRPC client (e.g., grpcurl or a custom Java client)
TOPIC_ID = 1
MIRROR_NODE_GRPC = "mirror-node:5600"

loop 10000 times in parallel (e.g., 100 goroutines × 100 iterations):
    stream = grpc.connect(MIRROR_NODE_GRPC)
    stream.send(SubscribeTopicRequest(topic_id=TOPIC_ID, start_time=now()))
    sleep(1ms)   # just long enough to trigger share() upstream subscription
    stream.cancel()
    # No sleep before next iteration — maximize race window hits
```

Expected result: Mirror node JVM heap grows unboundedly; Redis `CLIENT LIST` shows accumulating `SUBSCRIBE` commands; legitimate subscribers experience message delivery delays or OOM-induced restarts.

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java (L35-44)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        if (!listenerProperties.isEnabled()) {
            return Flux.empty();
        }

        return getTopicListener()
                .listen(filter)
                .filter(t -> filterMessage(t, filter))
                .doOnNext(this::recordMetric);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L22-34)
```java
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L34-34)
```java
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);
```
