The code references are accurate. Let me verify the exact behavior before rendering a verdict.

**Verified code facts:**

- `getSharedListener` at line 61: `topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic))` [1](#0-0) 
- `subscribe` at line 74: `.doOnCancel(() -> unsubscribe(topic))` and line 79: `.share()` [2](#0-1) 
- `unsubscribe` at line 83: `topicMessages.remove(topic.getTopic())` — removes by key only, not by value/instance [3](#0-2) 

Both structural flaws are confirmed present. The race is real: `ConcurrentHashMap.computeIfAbsent` holds a per-bin lock during the mapping function, so a concurrent `remove()` on the same key blocks and then fires immediately after the new value is inserted. The non-instance-specific `remove(key)` means any orphaned `Flux` that later cancels will evict whatever is currently registered — not the specific instance that triggered the cancel.

---

## Audit Report

## Title
Race Condition in `RedisTopicListener`: `computeIfAbsent` / `remove()` Interleaving Causes Orphaned Flux Instances and Map Corruption

## Summary
`RedisTopicListener.getSharedListener` uses `ConcurrentHashMap.computeIfAbsent` to lazily create and cache a shared `Flux` per topic. The `unsubscribe` callback, wired via `doOnCancel`/`doOnComplete`, calls `topicMessages.remove(topic.getTopic())` — a key-only removal. These two operations, combined with the `ConcurrentHashMap` bin-lock semantics, create a race where a freshly inserted `Flux` is immediately evicted from the map, and where any orphaned `Flux` that later cancels silently removes a legitimately registered successor entry.

## Finding Description

**Flaw 1 — Post-insert removal race**

`ConcurrentHashMap.computeIfAbsent` holds a per-bin lock for the duration of the mapping function. A concurrent `remove()` on the same key blocks on that lock and executes immediately after it is released — after the new value has been inserted. The sequence:

```
T1: last subscriber of Flux E cancels
    → doOnCancel fires → unsubscribe() → remove("topic.X") [blocks: T2 holds bin lock]

T2: new subscriber → computeIfAbsent("topic.X")
    → key absent → subscribe() → Flux F created → inserted → lock released → Flux F returned

T1 (unblocked): remove("topic.X") executes → Flux F evicted from map

T2 caller: holds Flux F, subscribes, receives messages — but Flux F is NOT in the map
``` [1](#0-0) [3](#0-2) 

**Flaw 2 — Non-instance-specific removal (cascade)**

`unsubscribe()` calls `topicMessages.remove(topic.getTopic())`, which removes *any* entry for that key. When orphaned Flux F (active, with live subscribers, but absent from the map) eventually has its last subscriber cancel, its `doOnCancel` fires and removes whatever `Flux G` is *currently* registered in the map. This corrupts the registry for all future subscribers on that topic and the cycle repeats. [4](#0-3) [3](#0-2) 

**Why `.share()` does not mitigate this**

`.share()` (`publish().refCount()`) resubscribes upstream when a new subscriber arrives on a flux whose refCount has dropped to 0. An orphaned `Flux` therefore stays alive and holds its `ReactiveRedisMessageListenerContainer` subscription as long as any subscriber is attached. Its eventual cancellation still fires `doOnCancel`, which executes the corrupting `remove()`. [5](#0-4) 

## Impact Explanation

Each race cycle leaks one `ReactiveRedisMessageListenerContainer` subscription and one `Flux` pipeline. Because `unsubscribe()` removes the current map entry rather than the specific cancelled instance, every orphaned `Flux` that later cancels evicts a legitimately registered successor, forcing the next subscriber to create yet another upstream connection. Under sustained triggering this exhausts Redis connections, Reactor scheduler threads, and heap. The sharing invariant is permanently broken for the affected topic: subscribers that should share one upstream connection each hold independent ones, multiplying load linearly with attacker-controlled cancel/subscribe cycles.

## Likelihood Explanation

No authentication or privilege is required beyond the ability to open a gRPC topic subscription (the normal public API). The race window is narrow on a lightly loaded system but widens under concurrent load (multiple scheduler threads, GC pauses). An attacker can deliberately widen the window by issuing many concurrent subscribe/cancel pairs on the same topic. The attack is repeatable and automatable with a simple gRPC client loop.

## Recommendation

1. **Use instance-specific removal.** Replace `topicMessages.remove(topic.getTopic())` with `topicMessages.remove(topic.getTopic(), fluxInstance)` (the two-argument `ConcurrentHashMap.remove(key, value)` form). This ensures only the specific `Flux` that triggered the cancel removes its own entry, preventing orphaned instances from evicting successors.

2. **Eliminate the post-insert removal race.** Use `compute()` instead of separate `computeIfAbsent` + `remove()` calls, or use a `ConcurrentHashMap` entry that wraps both the `Flux` reference and a cancelled flag, checked atomically.

3. **Consider `computeIfAbsent` + conditional remove pattern.** After `computeIfAbsent` returns, verify the returned instance is still the one in the map before subscribing. On cancel, only remove if `map.get(key) == this`.

## Proof of Concept

```
// Pseudocode — gRPC client loop
for (int i = 0; i < N; i++) {
    Subscription s1 = stub.subscribeTopic(topicX);   // triggers computeIfAbsent → Flux F_i inserted
    Subscription s2 = stub.subscribeTopic(topicX);   // returns same Flux F_i (or races)
    s1.cancel();                                      // if last subscriber: doOnCancel → remove(topicX)
    // race: concurrent computeIfAbsent for topicX may have just inserted F_{i+1}
    // remove() evicts F_{i+1}; s2 still holds F_i (orphaned)
    s2.cancel();                                      // F_i's doOnCancel → remove(topicX) evicts F_{i+2}
}
// After N iterations: N orphaned Flux instances, N leaked Redis subscriptions,
// topicMessages map entry for topicX is absent or points to a stale instance.
```

Each iteration leaks one Redis connection. The `topicMessages` map entry for the targeted topic is left absent or pointing to a stale `Flux`, forcing every subsequent legitimate subscriber to create a new upstream connection rather than sharing.

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
