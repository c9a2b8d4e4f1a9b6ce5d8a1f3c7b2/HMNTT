### Title
Unconditional `ConcurrentHashMap.remove()` in `unsubscribe()` Silently Evicts a Concurrent Subscriber's Active Flux

### Summary
In `RedisTopicListener.unsubscribe()`, the call `topicMessages.remove(topic.getTopic())` is unconditional — it removes whatever value is currently in the map for that key, not specifically the Flux that triggered the cancel. A concurrent `computeIfAbsent` in `getSharedListener()` can race with this remove, causing a freshly inserted, fully active Flux to be silently deleted from the map. Any unprivileged gRPC client can repeatedly trigger this by rapidly subscribing and cancelling, causing unbounded accumulation of orphaned Redis subscriptions for the same topic.

### Finding Description
**Exact code path:**

- `getSharedListener()` — [1](#0-0) 
- `subscribe()` registers `doOnCancel(() -> unsubscribe(topic))` — [2](#0-1) 
- `unsubscribe()` performs an unconditional key-only remove — [3](#0-2) 

**Root cause:** `ConcurrentHashMap.remove(key)` (single-argument form) removes whatever value is currently mapped to `key`, regardless of which Flux instance triggered the removal. The two-argument form `remove(key, value)` — which only removes if the value matches — is never used.

**Exploit flow:**

1. Attacker calls `getSharedListener("topic.X")` → `computeIfAbsent` creates **Flux_1**, inserts it into the map.
2. Attacker immediately cancels → `.share()` sees zero subscribers → upstream cancel fires → `doOnCancel` queues `unsubscribe(topic)`.
3. Before `unsubscribe()` executes `remove()`, a legitimate Subscriber B calls `getSharedListener("topic.X")` → `computeIfAbsent` finds no entry (or the entry is mid-removal) → creates **Flux_2**, inserts it into the map.
4. `unsubscribe()` now executes `topicMessages.remove("topic.X")` → **removes Flux_2** from the map, even though Flux_2 is live and Subscriber B is actively subscribed to it.

**Why existing checks fail:** `ConcurrentHashMap` guarantees atomicity of individual operations (`computeIfAbsent` and `remove` each individually), but provides no atomicity across the logical sequence "cancel Flux_1 → remove its map entry." The remove in step 4 cannot distinguish between Flux_1 (the one being cancelled) and Flux_2 (the freshly inserted one).

### Impact Explanation
After step 4, the map has no entry for `"topic.X"`. Every subsequent subscriber creates a brand-new Redis subscription (Flux_3, Flux_4, …), each independently consuming a Redis connection and listener slot. The shared-listener design — whose entire purpose is to multiplex all subscribers onto a single Redis subscription per topic — is defeated. With enough rapid subscribe/cancel cycles, the attacker can exhaust Redis connection pool resources or trigger Redis listener limits, degrading or denying service for all legitimate subscribers of that topic.

### Likelihood Explanation
Any unauthenticated or low-privilege gRPC client that can call the `subscribeTopic` RPC can trigger this. No special knowledge is required beyond knowing a valid topic ID. The race window is narrow but reliably widened by the async nature of Reactor's cancel propagation through `.share()` — the `doOnCancel` callback fires on a scheduler thread, giving the attacker a consistent window to insert a new subscriber between the cancel signal and the `remove()` call. The attack is trivially repeatable in a tight loop.

### Recommendation
Replace the single-argument `remove` with the two-argument `ConcurrentHashMap.remove(key, value)` overload, passing the specific Flux instance being cancelled:

```java
// In subscribe(), capture the Flux reference before returning
Flux<TopicMessage> flux = container
    .flatMapMany(...)
    ...
    .share();

// Pass the specific flux instance to unsubscribe
flux.doOnCancel(() -> topicMessages.remove(topic.getTopic(), flux))
    .doOnComplete(() -> topicMessages.remove(topic.getTopic(), flux));
return flux;
```

This ensures that only the exact Flux instance that triggered the cancel is removed, and a concurrently inserted Flux_2 is never evicted.

### Proof of Concept
**Reproducible steps (pseudo-code / integration test):**

```java
// 1. Attacker subscribes to topic 1
Disposable attacker = redisTopicListener
    .listen(filterForTopic(1))
    .subscribe();

// 2. Immediately cancel — triggers doOnCancel -> unsubscribe()
attacker.dispose();

// 3. Race: legitimate subscriber B subscribes before remove() executes
//    (use a CountDownLatch or Thread.sleep(1) to widen the window)
Flux<TopicMessage> sharedFlux = redisTopicListener.getSharedListener(filterForTopic(1));
Disposable subscriberB = sharedFlux.subscribe();

// 4. Assert: the map no longer contains an entry for topic 1
//    even though subscriberB is actively subscribed
Field field = RedisTopicListener.class.getDeclaredField("topicMessages");
field.setAccessible(true);
Map<?, ?> map = (Map<?, ?>) field.get(redisTopicListener);
assert map.get("topic.1") == null; // map entry was silently removed

// 5. New subscriber C gets a brand-new Flux (separate Redis subscription)
Disposable subscriberC = redisTopicListener.listen(filterForTopic(1)).subscribe();
// subscriberB and subscriberC are now on different Redis subscriptions
// Repeat in a loop to exhaust Redis connections
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L74-75)
```java
                .doOnCancel(() -> unsubscribe(topic))
                .doOnComplete(() -> unsubscribe(topic))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L82-85)
```java
    private void unsubscribe(Topic topic) {
        topicMessages.remove(topic.getTopic());
        log.info("Unsubscribing from {}", topic);
    }
```
