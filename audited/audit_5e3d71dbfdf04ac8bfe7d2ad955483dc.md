### Title
Permanently Cached Stale `ReactiveRedisMessageListenerContainer` Causes Unrecoverable Subscription Failure After Redis Restart

### Summary
In `RedisTopicListener`, the `container` Mono is terminated with `.cache()` (line 55), which permanently memoizes the first successfully created `ReactiveRedisMessageListenerContainer`. After a Redis server restart, the cached container holds a stale connection; the subscribe-level `retryWhen` (line 78) loops indefinitely re-using the same broken container because `.cache()` short-circuits re-subscription to the upstream Mono, meaning the container-level retry (line 54) is never re-triggered. All active and new topic subscriptions silently stop delivering messages with no terminal error propagated to callers.

### Finding Description
**Exact code path:**

- `RedisTopicListener.java` constructor, lines 47–55: the `container` Mono is built with `Mono.defer(...)` + `.retryWhen(...)` + `.cache()`. The `.cache()` operator subscribes to the upstream exactly once; on success it stores the emitted `ReactiveRedisMessageListenerContainer` and replays it to all future subscribers without re-executing the upstream pipeline.
- `subscribe()`, lines 71–79: every call to `container.flatMapMany(r -> r.receive(...))` resolves immediately from the cache. The `.retryWhen(Retry.backoff(Long.MAX_VALUE, interval)...)` at line 78 retries the entire `container.flatMapMany(...)` chain on error — but because `container` is cached, each retry receives the **same stale container object**, never a fresh one.
- `getSharedListener()`, line 61: the broken `Flux` returned by `subscribe()` is stored in `topicMessages` (a `ConcurrentHashMap`). Because the Flux never terminates (retries are `Long.MAX_VALUE`), `doOnCancel`/`doOnComplete` (lines 74–75) never fire, so the broken Flux is never evicted from the map. All subsequent callers for the same topic receive the same broken shared Flux.

**Root cause:** The design assumes the `ReactiveRedisMessageListenerContainer` instance is valid for the lifetime of the process. After a Redis server restart that invalidates the underlying connection, the container cannot self-heal at the object level. The container-level retry guard (line 54) is a one-shot mechanism gated by `.cache()` — it fires only during initial startup, not after post-startup failures.

**Failed assumption:** That a successfully constructed `ReactiveRedisMessageListenerContainer` will remain usable indefinitely, or that the subscribe-level retry is sufficient to recover from a broken container (it is not, because it replays the cached broken instance).

### Impact Explanation
All gRPC `subscribeTopic` calls routed through `RedisTopicListener` (i.e., when `listenerProperties.type == REDIS`) stop delivering `TopicMessage` events after a Redis restart. The subscriber's Flux never terminates — it silently retries forever — so callers receive no messages and no error signal. This is a complete, persistent denial-of-service for the real-time HCS topic subscription feature. Recovery requires a full application restart. No data is corrupted, but availability of the primary streaming path is lost.

### Likelihood Explanation
Redis restarts are routine operational events (rolling upgrades, OOM kills, failovers). No attacker capability is required to trigger the broken state — it occurs automatically on any Redis process restart. An unprivileged gRPC client need only hold an open `subscribeTopic` stream (or open a new one) after the restart to be permanently stuck in the broken retry loop. Because the broken Flux is shared and cached in `topicMessages`, a single restart affects every subscriber on every topic simultaneously. The condition is repeatable on every Redis restart.

### Recommendation
Replace the unconditional `.cache()` with a cache that can be invalidated on error, or restructure so that a new `ReactiveRedisMessageListenerContainer` is created on each retry cycle:

1. **Remove `.cache()` and use `Mono.defer` per retry**: wrap the entire container creation inside the subscribe-level retry so each retry attempt constructs a fresh container. Gate concurrent creation with a `Mono.fromCallable` + `publishOn` or an `AtomicReference` with CAS.
2. **Alternatively, use `.cache(Duration)` or a `ReplayProcessor` with TTL** so the cached value expires and the upstream is re-subscribed after a configurable window.
3. **Evict `topicMessages` on container-level error**: ensure that when the container fails post-startup, all entries in `topicMessages` are cleared so new subscribers trigger a fresh `subscribe()` call rather than receiving the cached broken Flux.
4. **Add a health indicator** that detects the stuck-retry state and surfaces it via the actuator, enabling automated restarts.

### Proof of Concept
1. Start the mirror-node gRPC service with `listenerProperties.type=REDIS` pointing at a live Redis instance.
2. Open a gRPC `subscribeTopic` stream for any topic (e.g., topic ID 1). Confirm messages are received.
3. Restart the Redis server process (simulating a network partition or OOM kill).
4. Observe that the gRPC stream remains open but no further messages are delivered, even after Redis is fully back online and publishers are writing to `topic.1`.
5. Inspect logs: repeated `"Error listening for messages"` entries appear at the subscribe-level retry interval, but no `"Attempting to connect to Redis"` / `"Connected to Redis"` log lines appear (confirming the container-level retry is never re-triggered).
6. Open a **new** gRPC `subscribeTopic` stream for the same topic. It also receives no messages — `topicMessages.computeIfAbsent` returns the same cached broken Flux (line 61).
7. Only a full JVM restart of the gRPC service restores message delivery. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L47-55)
```java
        this.container = Mono.defer(() -> Mono.just(new ReactiveRedisMessageListenerContainer(connectionFactory)))
                .name(METRIC)
                .tag(METRIC_TAG, "redis")
                .tap(Micrometer.observation(observationRegistry))
                .doOnError(t -> log.error("Error connecting to Redis: ", t))
                .doOnSubscribe(s -> log.info("Attempting to connect to Redis"))
                .doOnSuccess(c -> log.info("Connected to Redis"))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(8)))
                .cache();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-79)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L82-85)
```java
    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```
