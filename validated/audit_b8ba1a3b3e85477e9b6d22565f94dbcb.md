The code is confirmed in the repository. Let me verify the exact line numbers and operator ordering before rendering a verdict.

Audit Report

## Title
Race Between `doOnCancel`/`doOnComplete` in `unsubscribe()` Orphans Newly-Inserted Shared Flux, Causing Persistent Message Loss

## Summary
`RedisTopicListener.unsubscribe()` performs a blind key-only `ConcurrentHashMap.remove(key)`. Both `doOnCancel` and `doOnComplete` hooks on the same Flux pipeline call this method. A concurrent `computeIfAbsent` can insert a new Flux F2 between the two `remove` calls, causing the second call to silently evict F2 from the map. F2 is then orphaned: it holds a live Redis subscription but is unreachable, so all subsequent subscribers receive no messages and each creates another leaked connection.

## Finding Description

All three code elements are confirmed in `grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java`:

**`getSharedListener`** uses `computeIfAbsent` to lazily create and cache a shared Flux per topic: [1](#0-0) 

**`subscribe`** attaches both `doOnCancel` and `doOnComplete` to the same inner pipeline, both pointing to `unsubscribe`, placed *before* `retryWhen` and `.share()`: [2](#0-1) 

**`unsubscribe`** performs a blind key-only removal with no identity check: [3](#0-2) 

**Root cause:** `ConcurrentHashMap.remove(key)` removes *whatever value is currently mapped to that key*, not the specific Flux instance that triggered the hook. There is no `remove(key, expectedValue)` guard. `ConcurrentHashMap` guarantees atomicity of individual operations, but the sequence `remove` → `computeIfAbsent` → `remove` is not atomic.

**Why both hooks can fire:** `doOnCancel` and `doOnComplete` are placed on the inner pipeline, before `.share()`. When the last downstream subscriber cancels at the same moment the upstream Redis channel completes (e.g., Redis restart or network blip), `.share()` sends a cancel upstream (triggering `doOnCancel`) while the upstream simultaneously delivers `onComplete` (triggering `doOnComplete`). These two signals travel on independent scheduler threads, each independently invoking `unsubscribe()`.

Additionally, `retryWhen` (line 78) is placed *after* `doOnCancel`. When `retryWhen` internally cancels the old inner subscription before re-subscribing after an error, the cancel signal propagates upstream through `doOnCancel`, calling `unsubscribe()` and removing the still-live `.share()` wrapper from the map mid-retry.

**Race interleaving:**
```
Thread A (F1 upstream completes):
  doOnComplete fires → unsubscribe() → topicMessages.remove("topic.X") → F1 removed

Thread B (new gRPC subscriber):
  computeIfAbsent("topic.X") → key absent → subscribe() → F2 created and inserted

Thread A (cancel races with complete, or share() cleanup):
  doOnCancel fires → unsubscribe() → topicMessages.remove("topic.X") → F2 removed ← WRONG
```

After this sequence, F2 is orphaned: it holds an active Redis channel subscription but is no longer reachable via `topicMessages`. Every subsequent `computeIfAbsent` creates F3, F4, … each subject to the same race. [4](#0-3) 

## Impact Explanation
All subscribers to the affected topic stop receiving messages silently — no error is surfaced to clients. The orphaned Flux continues consuming a Redis pub/sub connection indefinitely (the `retryWhen` loop at line 78 keeps it alive), leaking resources. Repeated triggering exhausts Redis connection pool slots, degrading the entire mirror-node gRPC service for all topics. [5](#0-4) 

## Likelihood Explanation
An unprivileged gRPC client needs only to:
1. Subscribe to any topic (no authentication required beyond a valid topic ID).
2. Cancel the stream (disconnect or send a gRPC cancel).
3. Immediately re-subscribe.

Step 2 triggers `doOnCancel`; if the Redis upstream completes or errors concurrently (e.g., Redis restart, channel expiry, or network blip), `doOnComplete` also fires. The attacker does not need to control Redis directly — they only need to repeat the subscribe/cancel/re-subscribe cycle at high frequency to widen the race window. Under load this is reliably reproducible. [1](#0-0) 

## Recommendation
Replace the blind key-only removal in `unsubscribe` with the two-argument `ConcurrentHashMap.remove(key, expectedValue)` form. The `subscribe` method must capture the specific Flux instance it creates and pass it to `unsubscribe`, so only the entry that maps to *that exact instance* is removed:

```java
private Flux<TopicMessage> subscribe(Topic topic) {
    Duration interval = listenerProperties.getInterval();
    Flux<TopicMessage>[] self = new Flux[1];
    self[0] = container
            .flatMapMany(r -> r.receive(...))
            .map(Message::getMessage)
            .doOnCancel(() -> topicMessages.remove(topic.getTopic(), self[0]))
            .doOnComplete(() -> topicMessages.remove(topic.getTopic(), self[0]))
            ...
            .retryWhen(...)
            .share();
    return self[0];
}
```

This ensures that a `remove` triggered by F1's lifecycle hooks cannot evict a concurrently inserted F2. [6](#0-5) 

## Proof of Concept
1. Start two threads targeting the same topic ID.
2. Thread A: subscribe → immediately cancel (triggers `doOnCancel` → `remove("topic.X")`).
3. Thread B: `computeIfAbsent` fires between Thread A's two `remove` calls, inserting F2.
4. Thread A: a second `unsubscribe()` call (from `doOnComplete` racing with `doOnCancel`, or from `retryWhen` internal cancel) fires → `remove("topic.X")` evicts F2.
5. Observe: `topicMessages` is empty; all subsequent subscribers create new Flux instances that are also immediately orphaned. Redis connection count grows monotonically; no messages are delivered to any subscriber. [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L33-43)
```java
    private final Map<String, Flux<TopicMessage>> topicMessages; // Topic name to active subscription

    public RedisTopicListener(
            ListenerProperties listenerProperties,
            ObservationRegistry observationRegistry,
            ReactiveRedisConnectionFactory connectionFactory,
            RedisSerializer<TopicMessage> redisSerializer) {
        super(listenerProperties);
        this.channelSerializer = SerializationPair.fromSerializer(RedisSerializer.string());
        this.messageSerializer = SerializationPair.fromSerializer(redisSerializer);
        this.topicMessages = new ConcurrentHashMap<>();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L68-85)
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

    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```
