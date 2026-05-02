### Title
Unprivileged Subscriber Can Cause Permanent Message Loss via `.share()` Reference Count Drop to Zero in `RedisTopicListener`

### Summary
In `RedisTopicListener.subscribe()`, the `.share()` operator is used to multicast a Redis channel subscription to multiple gRPC clients. When the last subscriber cancels, `.share()` drops its reference count to zero and cancels the upstream, which triggers `doOnCancel(() -> unsubscribe(topic))`, removing the topic entry from `topicMessages`. Any messages published to the Redis channel during the window between upstream cancellation and the next `computeIfAbsent`-driven re-subscription are permanently lost. Any unprivileged gRPC client can trigger this by being the last subscriber and cancelling their stream.

### Finding Description

**Exact code path:**

In `grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java`:

- `getSharedListener()` (lines 59–62) uses `topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic))` to retrieve or create a shared `Flux<TopicMessage>` per topic.
- `subscribe()` (lines 68–80) builds the Flux chain:
  ```
  container.flatMapMany(r -> r.receive(...))   // Redis channel subscription
      .map(Message::getMessage)
      .doOnCancel(() -> unsubscribe(topic))     // line 74 — fires on upstream cancel
      .doOnComplete(() -> unsubscribe(topic))   // line 75
      ...
      .retryWhen(...)
      .share();                                 // line 79 — multicast with ref-counting
  ```
- `unsubscribe()` (lines 82–85) calls `topicMessages.remove(topic.getTopic())`.

**Root cause:**

Reactor's `.share()` operator maintains a subscriber reference count. When the count drops from 1 to 0 (last subscriber cancels), `.share()` propagates a cancel signal upstream through the entire chain. This cancel signal reaches `doOnCancel` at line 74, which calls `unsubscribe(topic)`, removing the key from `topicMessages`. The underlying `ReactiveRedisMessageListenerContainer` subscription is torn down at this point.

The failed assumption is that `.share()` will seamlessly re-subscribe when a new subscriber arrives. While `.share()` does re-subscribe its upstream on the next subscriber, there is an unavoidable temporal gap:

1. Last subscriber cancels → `.share()` cancels upstream → `doOnCancel` fires → `topicMessages.remove(key)` → Redis channel unsubscribed.
2. Messages published to the Redis channel during this window are silently dropped — there is no subscriber and no buffer.
3. Next gRPC client calls `getSharedListener()` → `computeIfAbsent` creates a new `subscribe(topic)` call → new Redis channel subscription established.

Steps 1 and 3 are not atomic. The `ConcurrentHashMap.computeIfAbsent` is atomic in isolation, but the removal in `unsubscribe()` and the subsequent `computeIfAbsent` are not coordinated, leaving a real gap.

**Exploit flow:**

1. Attacker (unprivileged gRPC client) subscribes to topic `T` — becomes the sole subscriber.
2. Attacker cancels their gRPC stream (e.g., drops the connection or sends a client-side cancel).
3. `.share()` ref count → 0; upstream cancelled; `doOnCancel` removes `T` from `topicMessages`; Redis unsubscribes from channel `topic.<id>`.
4. Consensus node publishes messages to Redis channel `topic.<id>` — no listener exists; messages are dropped by Redis pub/sub (fire-and-forget, no persistence).
5. Legitimate subscriber connects to topic `T`; `computeIfAbsent` creates a new subscription.
6. Legitimate subscriber never receives the messages published in step 4 — they are permanently lost.

**Why existing checks are insufficient:**

- `retryWhen` (line 78) only handles errors/exceptions, not the cancel-then-resubscribe lifecycle.
- `computeIfAbsent` (line 61) is atomic but does not close the temporal gap between removal and re-insertion.
- There is no replay buffer, no Redis Streams (persistent), and no sequence-number gap detection — Redis pub/sub is inherently lossy on missed windows.
- `SharedTopicListener.listen()` applies `onBackpressureBuffer` (line 24 of `SharedTopicListener.java`) only for per-subscriber backpressure, not for the upstream gap scenario.

### Impact Explanation

Any messages published to a Redis topic channel during the subscription gap are permanently undeliverable to all subsequent gRPC subscribers of that topic. This directly violates the mirror node's correctness guarantee of exporting all topic messages. Affected clients will observe a sequence gap in `TopicMessage` consensus sequence numbers with no error signal — the stream simply resumes from the next message after the gap. Severity is **Medium**: data integrity is compromised for real-time subscribers, but historical data is still accessible via the polling/database path.

### Likelihood Explanation

The attack requires no credentials, no special network position, and no knowledge of internal state beyond the target topic ID (which is public on-chain). Any gRPC client can open and immediately cancel a subscription. The window of message loss depends on message publication rate and reconnection latency (default retry interval is 500 ms per `ListenerProperties`, line 30), making it reliably reproducible under moderate message throughput. The attack is repeatable: the attacker can cycle subscribe/cancel indefinitely to suppress message delivery.

### Recommendation

1. **Replace `.share()` with `.publish().refCount(1, <grace-period>)`** or **`.publish().autoConnect()`** with a configurable grace period (e.g., equal to `listenerProperties.getInterval()`). This keeps the upstream Redis subscription alive for a short window after the last subscriber cancels, eliminating the gap for transient subscriber churn.

2. **Decouple teardown from `.share()` cancellation**: move `unsubscribe(topic)` out of `doOnCancel`/`doOnComplete` and instead use a scheduled cleanup that only removes the entry after confirming no new subscriber has arrived within the grace window.

3. **Use Redis Streams instead of pub/sub** for durable, replayable message delivery, eliminating the inherent fire-and-forget loss of Redis pub/sub.

4. **Minimum viable fix**: change line 79 from `.share()` to `.publish().refCount(1, listenerProperties.getInterval())` so the upstream subscription is held open for at least one retry interval after the last subscriber leaves.

### Proof of Concept

```
# Precondition: mirror node running with REDIS listener, topic 0.0.12345 exists

# Step 1: Subscribe as the only client (attacker)
grpcurl -d '{"topicID": {"topicNum": 12345}}' \
  <mirror-node>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
ATTACKER_PID=$!

# Step 2: Confirm subscription is active (log shows "Creating shared subscription to topic.12345")

# Step 3: Cancel the attacker subscription — drops ref count to 0
kill $ATTACKER_PID
# Log shows "Unsubscribing from topic.12345" — Redis channel unsubscribed

# Step 4: Publish messages to Redis during the gap (simulating consensus node)
redis-cli PUBLISH topic.12345 <serialized-TopicMessage-bytes>
# No subscriber exists — message silently dropped

# Step 5: Legitimate subscriber connects
grpcurl -d '{"topicID": {"topicNum": 12345}}' \
  <mirror-node>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic

# Result: legitimate subscriber receives no message for step 4's publish.
# Sequence number gap is observable in the received TopicMessage stream.
```