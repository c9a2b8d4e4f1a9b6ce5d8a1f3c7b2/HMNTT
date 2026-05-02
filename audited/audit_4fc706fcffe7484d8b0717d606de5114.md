### Title
Race Condition in `RedisTopicListener`: `computeIfAbsent` / `remove()` Interleaving Causes Orphaned Flux Instances and Cascading Map Corruption (Resource-Exhaustion DoS)

### Summary
`getSharedListener` uses `ConcurrentHashMap.computeIfAbsent` to create and cache a shared `Flux`, while `unsubscribe` calls `topicMessages.remove(topic.getTopic())` keyed only on the topic string — not on the specific `Flux` instance. A concurrent cancel from one subscriber can race with a new `computeIfAbsent` call, causing the freshly-inserted `Flux` to be immediately evicted from the map. The orphaned `Flux` remains active and, when it is eventually cancelled, its own `doOnCancel` removes whatever entry is *currently* in the map, corrupting the registry for all future subscribers on that topic.

### Finding Description

**Exact code path:**

- `getSharedListener`, line 61: `topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic))`
- `subscribe`, line 74: `.doOnCancel(() -> unsubscribe(topic))`
- `unsubscribe`, line 83: `topicMessages.remove(topic.getTopic())`

**Root cause — two independent flaws that compound:**

1. **Post-insert removal race.** `ConcurrentHashMap.computeIfAbsent` holds a per-bin lock while the mapping function executes. A concurrent `remove()` for the same key blocks until the lock is released, then immediately removes the value that was just inserted. The caller of `computeIfAbsent` receives the new `Flux F` and subscribes to it, but the map entry is already gone.

2. **Non-instance-specific removal.** `unsubscribe()` calls `topicMessages.remove(topic.getTopic())` — it removes *any* entry for that topic key, not the specific `Flux` that was cancelled. An orphaned `Flux` (one that was evicted from the map but is still active with live subscribers) will, when its last subscriber eventually cancels, fire `doOnCancel` and remove whatever `Flux G` is *currently* registered in the map for that topic.

**Exploit flow:**

```
T1: Flux E in map, last subscriber cancels
    → doOnCancel fires → unsubscribe() → remove("topic.X") [blocks on bin lock]

T2: new subscriber calls computeIfAbsent("topic.X")
    → key absent → calls subscribe() → creates Flux F → inserts Flux F → releases lock
    → returns Flux F to caller

T1 (unblocked): remove("topic.X") executes → removes Flux F from map

T2 caller: subscribes to Flux F (active, receives messages, but NOT in map)

T3: next subscriber calls computeIfAbsent("topic.X")
    → key absent → creates Flux G → inserts Flux G

T2 caller cancels: Flux F's doOnCancel fires → remove("topic.X") → removes Flux G

... cascade repeats indefinitely
```

**Why existing checks are insufficient:**

`ConcurrentHashMap` provides atomicity per-operation but not across the `computeIfAbsent` → subscriber-attaches → `remove` sequence. The `.share()` operator's `refCount` resubscribes upstream when a new subscriber arrives on an orphaned `Flux`, so the orphan silently stays alive and continues to hold a Redis connection — and its eventual cancellation corrupts the next valid map entry.

### Impact Explanation

Each race cycle leaks one `ReactiveRedisMessageListenerContainer` subscription and one `Flux` pipeline. Because `unsubscribe()` removes the *current* map entry rather than the specific instance, every orphaned `Flux` that is later cancelled removes a legitimately-registered `Flux`, forcing the next subscriber to create yet another new subscription. Under sustained attack this exhausts Redis connections, thread-pool resources, and heap, constituting a non-network-based DoS. The sharing invariant is permanently broken for the affected topic: subscribers that should share one upstream connection each hold independent ones, multiplying load linearly with attacker-controlled cancel/subscribe cycles.

### Likelihood Explanation

No authentication or privilege is required. Any gRPC client that can open a topic subscription (the normal public API) can trigger this by rapidly subscribing and cancelling. The race window is narrow on a single-core machine but widens under load (multiple scheduler threads, GC pauses). An attacker can widen the window deliberately by issuing many concurrent subscribe/cancel pairs. The attack is repeatable and automatable with a simple gRPC client loop.

### Recommendation

1. **Key the removal on the specific `Flux` instance, not just the topic string.** Use `topicMessages.remove(topic.getTopic(), fluxInstance)` (the two-argument `ConcurrentHashMap.remove` which only removes if the value matches):

   ```java
   // capture the Flux reference at subscribe time
   private Flux<TopicMessage> subscribe(Topic topic) {
       Flux<TopicMessage>[] self = new Flux[1];
       self[0] = container
           .flatMapMany(...)
           ...
           .doOnCancel(() -> topicMessages.remove(topic.getTopic(), self[0]))
           .doOnComplete(() -> topicMessages.remove(topic.getTopic(), self[0]))
           ...
           .share();
       return self[0];
   }
   ```

2. **Use `compute` instead of `computeIfAbsent` + separate `remove`.** Replace the two-step pattern with a single atomic `compute` call that checks whether the `Flux` is still active before deciding to remove or retain the entry.

3. **Consider `Sinks.Many` with explicit lifecycle management** so that the active/inactive state of the shared publisher is tracked atomically alongside the map entry.

### Proof of Concept

```
1. Open gRPC stream S1 for topic T → Flux E created, inserted into map.
2. In a tight loop (e.g., 100 threads):
   a. Open gRPC stream Sn for topic T  (triggers computeIfAbsent)
   b. Immediately cancel Sn           (triggers doOnCancel → remove)
3. Observe via metrics/logs:
   - "Creating shared subscription to topic.T" logged far more than once
     (each log line = a new orphaned Redis subscription)
   - Redis connection count climbs monotonically
   - Memory grows without bound
4. After ~1000 iterations, Redis connection pool is exhausted;
   new subscribers receive errors or hang indefinitely.
```