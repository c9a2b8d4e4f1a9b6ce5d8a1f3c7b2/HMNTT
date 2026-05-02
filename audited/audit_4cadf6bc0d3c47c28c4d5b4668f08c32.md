### Title
Unbounded Per-Subscription Heap Allocation in `PollingTopicListener.poll()` via `getResultList()` Materialization Enables Heap Exhaustion DoS

### Summary
When the gRPC listener is configured with `POLL` type, each unauthenticated `subscribeTopic` call creates an independent `PollingContext` that invokes `findByFilter()` every 500 ms. `TopicMessageRepositoryCustomImpl.findByFilter()` calls `typedQuery.getResultList().stream()`, which fully materializes up to 5,000 `TopicMessage` objects (each carrying up to 6 KB of message payload per the protobuf spec) into a heap-resident `List<TopicMessage>` before returning. With many concurrent subscriptions and no per-client rate limiting or connection cap, the aggregate heap pressure across all concurrent polls can exhaust JVM heap and crash the node.

### Finding Description
**Exact code path:**

- `PollingTopicListener.listen()` (line 38): `Flux.defer(() -> poll(context))` — creates one independent polling loop per subscription.
- `PollingTopicListener.poll()` (lines 51–62): computes `pageSize = Math.min(limit, listenerProperties.getMaxPageSize())` where `maxPageSize` defaults to 5,000, then calls `Flux.fromStream(topicMessageRepository.findByFilter(newFilter))`.
- `TopicMessageRepositoryCustomImpl.findByFilter()` (line 60): `return typedQuery.getResultList().stream();` — `getResultList()` executes the SQL query and loads the **entire result set** into a `java.util.List<TopicMessage>` on the heap before the stream is returned to the reactive pipeline.

**Root cause:** The comment on line 60 acknowledges the deliberate choice: `// getResultStream()'s cursor doesn't work with reactive streams`. This means every poll eagerly allocates a full `List<TopicMessage>` of up to 5,000 objects. Unlike `SHARED_POLL` (which shares one poll across all subscribers via `.share()`), `POLL` type creates a completely independent polling loop per subscriber — N subscribers = N independent `getResultList()` calls firing concurrently.

**Why existing checks fail:**
- `maxPageSize = 5000` caps allocation *per poll*, not *aggregate across subscriptions*.
- The `boundedElastic` scheduler (line 31) limits concurrent thread execution (default: `10 × CPU_count` threads, queue of 100,000 tasks), but with enough subscriptions the executing threads each hold a full 5,000-object list simultaneously. On a 4-core node: 40 threads × 5,000 objects × ~6 KB/message = ~1.2 GB heap pressure from poll results alone, before JVM overhead.
- `ConsensusController.subscribeTopic()` (line 43) has no authentication, no per-IP connection limit, and no subscription count cap. `TopicMessageServiceImpl` tracks `subscriberCount` as a metric gauge only — it is never used to reject new subscriptions.
- The `POLL` type is not the default (`REDIS` is), but it is a documented, supported configuration option.

### Impact Explanation
On a node configured with `ListenerType.POLL`, an attacker can drive the JVM into `OutOfMemoryError` by holding many concurrent open gRPC streams. The JVM crash takes the gRPC service offline entirely. If 30%+ of mirror nodes in a deployment use this configuration, the network's query availability drops below the threshold described in the scope. Even below that threshold, a single node crash disrupts all clients connected to it and may trigger cascading load on remaining nodes.

### Likelihood Explanation
The attack requires zero privileges — `subscribeTopic` is an unauthenticated gRPC streaming RPC callable with `grpcurl` or any gRPC client. The attacker needs only network access to port 5600. Opening thousands of persistent gRPC streams is trivially scriptable. The `POLL` type is a real operational configuration (it is tested, documented, and selectable via `hiero.mirror.grpc.listener.type=POLL`). The attack is repeatable and does not require knowledge of valid topic IDs — any topic ID accepted by `topicExists()` suffices, and with `checkTopicExists=false` (the fallback path in `TopicMessageServiceImpl` line 100) even non-existent topics work.

### Recommendation
1. **Enforce a global subscription cap**: reject new `subscribeTopic` calls when `subscriberCount` exceeds a configurable threshold (e.g., `hiero.mirror.grpc.listener.maxSubscribers`).
2. **Replace `getResultList().stream()` with a true streaming/cursor approach** that does not materialize the full result set, or use Spring Data's `@QueryHints` with `HINT_FETCH_SIZE` and `ScrollableResults` wrapped in a custom `Spliterator` that is safe for reactive use.
3. **Add per-IP or per-client connection rate limiting** at the gRPC server level (e.g., via a `ServerInterceptor`).
4. **Prefer `SHARED_POLL` or `REDIS`** in production and document `POLL` as unsuitable for public-facing deployments.

### Proof of Concept
```bash
# 1. Configure the mirror node with POLL listener type:
#    hiero.mirror.grpc.listener.type=POLL

# 2. Open thousands of concurrent persistent subscriptions (no auth required):
for i in $(seq 1 2000); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 41110}}' \
    localhost:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done

# 3. Each subscription triggers poll() every 500ms.
#    findByFilter() calls getResultList() loading up to 5000 TopicMessage
#    objects per poll. With 40 concurrent boundedElastic threads each holding
#    a 5000-object list of ~6KB messages, heap pressure reaches ~1.2 GB+.

# 4. Monitor JVM heap:
#    jstat -gcutil <pid> 1000
#    Expected: rapid heap growth → Full GC thrashing → OutOfMemoryError →
#    JVM crash / service unavailability.
```