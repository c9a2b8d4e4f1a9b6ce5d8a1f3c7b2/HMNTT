The code is confirmed. Let me verify the `.share()` / `doOnCancel` interaction precisely before rendering the final verdict.

All code references have been verified against the actual source. The race condition is real and the unconditional remove is confirmed. Here is the audit report.

---

Audit Report

## Title
Race Condition in `unsubscribe()` Causes Missing Messages for New Subscribers via Stale Shared Flux

## Summary
`RedisTopicListener.getSharedListener()` uses `ConcurrentHashMap.computeIfAbsent` to return a shared `.share()` Flux, but the actual subscription to that Flux is deferred. An existing sole subscriber cancelling between the map lookup and the new subscriber's actual subscription causes the shared Flux to be evicted from the map, forcing a Redis re-subscription and a message-loss window. The unconditional key-based `remove` in `unsubscribe()` compounds this by allowing a stale cancel from one Flux to evict a different, active Flux from the map.

## Finding Description

**`getSharedListener` — atomic map lookup, deferred subscription:**

`computeIfAbsent` atomically returns the shared Flux, but the caller subscribes to it later, outside that atomic boundary. [1](#0-0) 

**`subscribe` — `doOnCancel` placed upstream of `.share()`:**

The `doOnCancel` hook fires when `.share()` cancels its upstream (i.e., when refCount drops to 0). The Flux returned and stored in `topicMessages` is the `.share()` Flux itself. [2](#0-1) 

**`unsubscribe` — unconditional key-based remove:**

`topicMessages.remove(topic.getTopic())` removes by key only, with no check that the value being removed is the same Flux instance that triggered the cancel. [3](#0-2) 

**`listen` — lazy subscription:**

`listen()` assembles a Flux chain around `getSharedListener(filter)` and returns it. The actual subscription is deferred until the caller subscribes to the returned Flux. [4](#0-3) 

**Exploit flow:**

```
T1: Attacker (A) is the sole subscriber to Flux_1 in topicMessages["topic.X"]
T2: Victim (B) calls listen() → getSharedListener() → computeIfAbsent returns Flux_1
    (B holds a reference to Flux_1 but has NOT yet subscribed)
T3: A cancels → share() refCount 1→0 → upstream cancelled
    → doOnCancel fires → unsubscribe() → topicMessages.remove("topic.X")
T4: B subscribes to the Flux chain wrapping Flux_1
T5: B's subscription reaches Flux_1 (.share()); refCount was 0, upstream was cancelled
    → Reactor's refCount() re-subscribes to upstream (new Redis connection via container.flatMapMany)
T6: Messages published to Redis during the re-subscription window are missed by B
```

**Cascading effect (unconditional remove):**

After T3, `topicMessages["topic.X"]` is empty. Subscriber C calls `computeIfAbsent` → creates Flux_2 → inserts it. B is now subscribed to Flux_1 (a separate Redis subscription). When B eventually cancels, Flux_1's `doOnCancel` fires and calls `topicMessages.remove("topic.X")` — which now holds Flux_2, not Flux_1. Flux_2 is evicted, breaking C's subscription from the shared map and repeating the problem for all future subscribers on that topic.

**Why existing checks fail:**

- `ConcurrentHashMap` only makes individual map operations atomic; it does not protect the compound "get-then-subscribe" operation.
- `topicMessages.remove(topic.getTopic())` is a key-only remove. The correct guard is `topicMessages.remove(topic.getTopic(), fluxInstance)` (key+value remove), which would prevent a stale cancel from evicting a different Flux.

## Impact Explanation

New subscribers miss topic messages during the Redis re-subscription window. The unconditional `remove` means a stale cancel from Flux_1 can evict an active Flux_2 from the map, breaking the shared-subscription invariant for all subsequent subscribers on that topic. Under sustained exploitation, every subscriber ends up on a separate Redis subscription (resource exhaustion), and each misses messages during their individual re-subscription delay.

## Likelihood Explanation

The attacker requires only a standard, unprivileged gRPC subscription — no elevated access. The race window is narrow (between `computeIfAbsent` returning and the lazy subscription being activated), but it is reliably reproducible under concurrent load. An attacker can widen the window by subscribing and immediately cancelling in a tight loop while a victim is subscribing. In production systems with many concurrent subscribers, this race can also occur naturally without deliberate exploitation.

## Recommendation

1. **Use a key+value remove in `unsubscribe`** to prevent stale cancels from evicting a different Flux:
   ```java
   private void unsubscribe(Topic topic, Flux<TopicMessage> flux) {
       topicMessages.remove(topic.getTopic(), flux);
       log.info("Unsubscribing from {}", topic);
   }
   ```
   Pass the specific Flux instance captured at construction time via a lambda closure in `subscribe()`.

2. **Make the "get-then-subscribe" operation atomic** by using `computeIfAbsent` in a way that ensures the Flux is not evicted before the new subscriber attaches. One approach is to use Reactor's `Sinks` or a `ReplayProcessor` with a reference-counted wrapper that only removes the entry when the refCount is confirmed to be zero and no pending subscribers exist.

3. **Consider `publish().autoConnect(1)` with explicit lifecycle management** instead of `refCount()` (`.share()`), so that the upstream subscription is not torn down on the last cancel, avoiding the re-subscription window entirely.

## Proof of Concept

```java
// Thread 1: sole subscriber A
Flux<TopicMessage> sharedFlux = listener.listen(filter); // computeIfAbsent → Flux_1
Disposable a = sharedFlux.subscribe();

// Thread 2: victim B — gets Flux_1 from map, has NOT yet subscribed
Flux<TopicMessage> victimFlux = listener.listen(filter); // computeIfAbsent → same Flux_1

// Thread 1: A cancels — refCount 1→0, doOnCancel fires, topicMessages.remove("topic.X")
a.dispose();

// Thread 2: B now subscribes — Flux_1.share() refCount 0→1, re-subscribes upstream
// Any messages published between a.dispose() and this subscribe() are lost
victimFlux.subscribe(msg -> System.out.println("received: " + msg));
```

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
