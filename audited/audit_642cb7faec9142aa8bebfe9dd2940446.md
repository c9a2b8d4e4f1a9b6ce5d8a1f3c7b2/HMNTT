### Title
Race Condition in `RedisTopicListener.getSharedListener()` Causes Permanent Redis Message Loss Window

### Summary
When the last subscriber to a Redis topic cancels, `doOnCancel` synchronously removes the topic from `topicMessages` via `unsubscribe()`. Between that removal and the next `computeIfAbsent` call establishing a new Redis subscription, any messages published to that Redis channel are permanently lost — Redis pub/sub does not buffer undelivered messages. Any unprivileged gRPC client can trigger this by subscribing and immediately cancelling.

### Finding Description

**Exact code path:**

`getSharedListener()` at [1](#0-0)  uses `ConcurrentHashMap.computeIfAbsent` to lazily create and cache a shared `Flux` per topic.

`subscribe()` at [2](#0-1)  builds the upstream chain and terminates with `.share()`. Critically, `doOnCancel` is placed **before** `.share()` in the operator chain, meaning it fires on the upstream when `.share()`'s internal subscriber count drops to zero (last subscriber cancels).

`unsubscribe()` at [3](#0-2)  unconditionally calls `topicMessages.remove(topic.getTopic())`.

**Root cause:** There is no atomic check-and-remove guard. The `doOnCancel` callback fires synchronously on the cancelling thread and removes the map entry. A concurrent `computeIfAbsent` on another thread that executes after the removal creates a brand-new `Flux` and a new Redis subscription. The gap between the `remove()` and the new subscription becoming active in Redis is a real, non-zero window during which the channel has zero listeners.

**Race window:**
```
Thread A (attacker):  subscribe → cancel → doOnCancel → topicMessages.remove("topic.X")
                                                                  ↑
                                                         [GAP: no Redis listener]
                                                                  ↓
Thread B (victim):    computeIfAbsent → subscribe(topic) → Redis SUBSCRIBE round-trip
```

Any message Redis publishes to `topic.X` during the gap is silently dropped — Redis pub/sub has no replay.

**Why existing checks are insufficient:**

- `ConcurrentHashMap` makes individual `computeIfAbsent` and `remove` calls thread-safe in isolation, but there is no atomic coordination between the `remove` in `unsubscribe()` and the `computeIfAbsent` in `getSharedListener()`. [4](#0-3) 
- The 1-second safety-check poll in `TopicMessageServiceImpl` [5](#0-4)  partially mitigates this by querying the database for missed messages, but only for already-connected subscribers. It does not help if the attacker repeatedly triggers the race to keep the window open, and it introduces mandatory latency for live delivery.
- The `retryWhen` on the upstream [6](#0-5)  handles Redis connection errors, not this logical removal race.

### Impact Explanation

Redis pub/sub messages published during the gap are permanently undeliverable via the live path. For a mirror node, this means HCS topic messages can be silently skipped in real-time streams. While the database safety-check partially compensates, it introduces up to 1-second delivery delays per attack cycle and does not cover the case where the attacker continuously churns subscriptions faster than the safety-check interval, effectively degrading live streaming to polling-only behavior for targeted topics.

### Likelihood Explanation

Any unauthenticated gRPC client can call `subscribeTopic` and immediately close the stream — this is standard gRPC client behavior and requires zero privileges. The `ConsensusController` wires the gRPC cancel handler directly to `disposable::dispose` [7](#0-6) , so a TCP RST or clean gRPC cancel both trigger the path. The attack is trivially repeatable in a tight loop from a single client.

### Recommendation

Replace the non-atomic remove-then-recreate pattern with one of the following:

1. **Do not remove on cancel; use `refCount` with a grace period**: Replace `.share()` with `.publish().refCount(1, Duration.ofSeconds(N))` so the upstream is kept alive for N seconds after the last subscriber leaves, absorbing reconnect races.
2. **Atomic replace-on-cancel**: In `unsubscribe()`, use `topicMessages.remove(key, value)` (the two-argument form) so the entry is only removed if it still holds the exact `Flux` instance being cancelled, preventing removal of a freshly-created replacement.
3. **Never remove; let `.share()` handle reconnect**: Remove `doOnCancel`/`doOnComplete` → `unsubscribe()` entirely and rely on `.share()`'s built-in upstream lifecycle management, accepting that idle subscriptions remain open.

### Proof of Concept

**Preconditions:** Mirror node running with `REDIS` listener type; Redis broker active; at least one message being published to a topic periodically.

**Steps:**
1. Open gRPC connection, call `subscribeTopic` for `topic.X` — this is the only subscriber, so `computeIfAbsent` creates Flux F1 and subscribes to Redis channel `topic.X`.
2. Immediately close the gRPC connection (TCP RST or clean cancel). This triggers `disposable::dispose` → `.share()` count = 0 → upstream cancel → `doOnCancel` → `topicMessages.remove("topic.X")`.
3. Concurrently (or in a tight loop), open a new gRPC connection for `topic.X`. `computeIfAbsent` sees no entry and calls `subscribe(topic)`, which issues a new Redis `SUBSCRIBE` command (async network round-trip).
4. Any message published to Redis channel `topic.X` between steps 2 and 3 (during the Redis `SUBSCRIBE` round-trip) is permanently dropped.
5. Repeat steps 1–4 in a loop at high frequency to continuously widen the effective gap and degrade live delivery for all subscribers of that topic.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-52)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
```
