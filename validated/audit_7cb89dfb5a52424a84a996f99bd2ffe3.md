I verified all code references against the actual source files before rendering a verdict.

**Verified facts:**

- `SharedTopicListener.listen()` calls `getSharedListener(filter)` eagerly at assembly time, not inside `Flux.defer()`. [1](#0-0) 
- `getSharedListener()` uses `computeIfAbsent` with no identity guard. [2](#0-1) 
- `doOnCancel` is placed **before** `.share()`, meaning it fires when `share()`'s refCount drops to 0 and it cancels its upstream — not per individual subscriber. [3](#0-2) 
- `unsubscribe()` performs a blind `topicMessages.remove(topic.getTopic())` with no check that the value being removed is the same `Flux` instance that registered the callback. [4](#0-3) 
- `publishOn(Schedulers.boundedElastic())` in `listen()` introduces a real, non-zero scheduling delay between assembly time (when `computeIfAbsent` runs) and subscription time, widening the race window. [5](#0-4) 

All structural claims in the report are confirmed by the actual code. The race condition, blind-remove corruption, and cascading orphan accumulation are all mechanically sound given Reactor's `publish().refCount()` semantics (which allow re-subscription after refCount drops to 0).

---

# Audit Report

## Title
Race Condition in `RedisTopicListener`: `computeIfAbsent`/`remove` Interleaving Causes Orphaned Subscriptions, Map Corruption, and Missed Messages

## Summary
`SharedTopicListener.listen()` retrieves a shared `Flux` reference via `computeIfAbsent` at assembly time, but the actual subscription is deferred until a downstream subscriber subscribes. If the last existing subscriber cancels in the window between those two events, `unsubscribe()` removes the entry from the map and a racing thread inserts a new `Flux` (F2). The original caller then subscribes to the now-orphaned F1, and when F1 eventually unsubscribes it blindly removes F2 from the map — corrupting the tracking state for all subsequent subscribers.

## Finding Description

**Exact code path:**

`SharedTopicListener.listen()` calls `getSharedListener()` eagerly at assembly time:

```java
// SharedTopicListener.java lines 21-26
public Flux<TopicMessage> listen(TopicMessageFilter filter) {
    return getSharedListener(filter)          // F1 obtained HERE (assembly time)
            .doOnSubscribe(...)
            .onBackpressureBuffer(...)
            .publishOn(Schedulers.boundedElastic(), ...);  // subscription deferred
}
``` [1](#0-0) 

`getSharedListener()` returns the `Flux` immediately via `computeIfAbsent`:

```java
// RedisTopicListener.java lines 59-62
protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
    Topic topic = getTopic(filter);
    return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
}
``` [2](#0-1) 

`subscribe()` places `doOnCancel` **before** `.share()`, so it fires when `share()`'s refCount drops to 0 (all subscribers cancel), not per-subscriber:

```java
// RedisTopicListener.java lines 68-80
return container.flatMapMany(...)
        .map(Message::getMessage)
        .doOnCancel(() -> unsubscribe(topic))   // fires when share() cancels upstream
        .doOnComplete(() -> unsubscribe(topic))
        ...
        .retryWhen(...)
        .share();
``` [3](#0-2) 

`unsubscribe()` performs a blind `remove()` with no identity check:

```java
// RedisTopicListener.java lines 82-85
private void unsubscribe(Topic topic) {
    topicMessages.remove(topic.getTopic());   // removes WHATEVER is in the map for this key
    log.info("Unsubscribing from {}", topic);
}
``` [4](#0-3) 

**Root cause:** The map operation (`computeIfAbsent`) and the actual subscription are not atomic. `ConcurrentHashMap` guarantees per-operation atomicity, but not across the `computeIfAbsent` → subscribe sequence. The `unsubscribe()` `remove()` call has no identity guard — it removes any value stored under the key, not specifically the `Flux` that triggered it. Reactor's `publish().refCount()` (used by `.share()`) allows re-subscription after refCount drops to 0, meaning an orphaned F1 can re-subscribe upstream and later corrupt the map entry for F2.

**Exploit flow:**

```
Thread A: computeIfAbsent("topic.1") → returns F1 (F1 is in map)
                                                    ↓
                              [last subscriber of F1 cancels]
                              [share() refCount → 0, upstream cancelled]
                              [doOnCancel fires → topicMessages.remove("topic.1")]
                                                    ↓
Thread B: computeIfAbsent("topic.1") → key absent → creates F2 → stores F2 in map
                                                    ↓
Thread A: subscribes to F1 → share() refCount was 0 → F1 re-subscribes upstream
          F1 is NOT in the map (F2 is)
          When Thread A cancels: F1's doOnCancel fires → topicMessages.remove("topic.1")
          → removes F2 (not F1) → F2 subscribers are now orphaned
```

## Impact Explanation

1. **Missed messages**: Between F1's upstream cancellation and F1's re-subscription, any messages published to the Redis channel for that topic are received by nobody. Thread A misses those messages permanently.
2. **Map state corruption**: F1's deferred `unsubscribe()` removes F2 from the map, causing all F2 subscribers to become orphaned. Their future cancellations will in turn remove F3, and so on — a cascading corruption of the tracking map.
3. **Redis resource leak**: Each race cycle creates an additional untracked Redis subscription. Under repeated exploitation, this exhausts Redis connection/subscription limits.
4. **Denial of service**: Accumulated orphaned subscriptions degrade service for all users of the gRPC topic subscription endpoint.

## Likelihood Explanation

The race window is the scheduling delay introduced by `publishOn(Schedulers.boundedElastic())` — a real, non-zero delay (thread pool scheduling latency). An unprivileged gRPC client can subscribe and cancel at will. Under moderate concurrency (multiple clients subscribing to the same topic), the race is reproducible without any special privileges. The cascading nature means the impact compounds over time with each triggered race.

## Recommendation

1. **Use `Flux.defer()` in `listen()`** to defer `getSharedListener()` until subscription time, eliminating the assembly-time/subscription-time gap:
   ```java
   return Flux.defer(() -> getSharedListener(filter))
           .doOnSubscribe(...)
           .onBackpressureBuffer(...)
           .publishOn(Schedulers.boundedElastic(), ...);
   ```
2. **Add an identity check in `unsubscribe()`** using `ConcurrentHashMap.remove(key, value)` to only remove the entry if it still maps to the specific `Flux` instance that registered the callback:
   ```java
   private void unsubscribe(Topic topic, Flux<TopicMessage> flux) {
       topicMessages.remove(topic.getTopic(), flux);
   }
   ```
3. **Consider wrapping the get-or-create-and-subscribe sequence** in a synchronized block or using a `compute()` operation that atomically handles both the map update and subscription registration.

## Proof of Concept

```java
// Pseudocode demonstrating the race
ExecutorService exec = Executors.newFixedThreadPool(3);

// Thread A: assembly time - gets F1
Flux<TopicMessage> pipeline = sharedTopicListener.listen(filter); // computeIfAbsent → F1

// Simulate: last subscriber of F1 cancels between assembly and subscription
existingSubscription.cancel(); // doOnCancel fires → topicMessages.remove("topic.1")

// Thread B: creates F2 and stores it
exec.submit(() -> sharedTopicListener.listen(filter).subscribe()); // computeIfAbsent → F2

// Thread A: now subscribes to F1 (re-subscribes upstream, F1 not in map)
pipeline.subscribe(); // F1 re-subscribes upstream, F2 is in map

// Thread A cancels: F1's doOnCancel fires → removes F2 from map
// F2 subscribers are now orphaned with an active but untracked Redis subscription
```

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
