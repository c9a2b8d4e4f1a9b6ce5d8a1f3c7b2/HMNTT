### Title
Unbounded gRPC Stream Lifetime Enables Resource Exhaustion via Indefinite Topic Subscriptions

### Summary
The `listen()` method in `CompositeTopicListener` imposes no maximum subscription duration, and the service layer explicitly returns `Flux.never()` as the termination signal when no `endTime` is provided. An unprivileged attacker can open many TCP connections — each carrying up to 5 concurrent streams — with no `endTime` and no `limit`, holding every stream open indefinitely and exhausting server file descriptors, Reactor scheduler threads, and gRPC connection slots.

### Finding Description

**Code path and root cause:**

In `TopicMessageServiceImpl.subscribeTopic()`, the termination signal for live streams is constructed by `pastEndTime()`: [1](#0-0) 

When `filter.getEndTime() == null`, this method returns `Flux.never()` — a stream that never emits a terminal signal. This is then used as the `takeUntilOther` argument: [2](#0-1) 

The two optional termination paths — `takeWhile` on `endTime` and `take` on `limit` — are both gated on client-supplied values: [3](#0-2) 

`TopicMessageFilter` defines both `endTime` and `limit` as optional with no server-enforced maximum: [4](#0-3) 

`CompositeTopicListener.listen()` itself adds no timeout or duration cap before delegating: [5](#0-4) 

**Why existing checks fail:**

The only connection-level guard is `maxConcurrentCallsPerConnection = 5`: [6](#0-5) 

This is a **per-connection** limit, not a global one. An attacker opening *N* TCP connections gets *5N* concurrent indefinite streams. There is no global `maxSubscribers` enforcement — `subscriberCount` is a metrics gauge only: [7](#0-6) 

`ListenerProperties` contains no per-subscriber or global timeout: [8](#0-7) 

### Impact Explanation

Each open stream holds: a gRPC HTTP/2 stream slot, a Reactor `Flux` subscription chain, a Redis pub/sub channel subscription or a polling scheduler task (depending on `ListenerType`), and an OS file descriptor for the underlying TCP connection. With no server-side duration limit and no global subscriber cap, an attacker can accumulate thousands of indefinite streams, leading to file descriptor exhaustion, Netty worker thread starvation, Redis connection pool saturation, and eventual denial of service for legitimate subscribers. Severity: **High**.

### Likelihood Explanation

No authentication is required to call the topic subscription endpoint — it is a public gRPC service. The attack requires only a gRPC client library and the ability to open TCP connections to the server port. It is trivially scriptable: open connections in a loop, subscribe with a valid `topicId`, omit `endTime` and `limit`. The attack is repeatable and can be sustained from a single machine or distributed across multiple IPs to bypass any IP-level rate limiting at the network edge. Likelihood: **High**.

### Recommendation

1. **Enforce a server-side maximum subscription duration**: Add a `maxSubscriptionDuration` field (e.g., `Duration`, default 1 hour) to `GrpcProperties` or `ListenerProperties`, and apply `.timeout(maxDuration)` or `.take(maxDuration)` in `TopicMessageServiceImpl.subscribeTopic()` unconditionally, regardless of whether the client supplies `endTime`.
2. **Enforce a global concurrent subscriber limit**: Use `subscriberCount` (already tracked) to reject new subscriptions when a configurable `maxSubscribers` threshold is exceeded, returning `RESOURCE_EXHAUSTED` gRPC status.
3. **Cap `endTime` distance from now**: In `TopicMessageFilter` validation, reject requests where `endTime - now` exceeds a server-configured maximum.
4. **Configure Netty `maxConnectionAge`**: Set a maximum connection age on the Netty/gRPC server so long-lived connections are periodically recycled.

### Proof of Concept

```python
import grpc
import threading
# proto: hiero/mirror/api/proto/consensus_service.proto

def open_indefinite_stream(stub, topic_id):
    request = ConsensusTopicQuery(
        topicID=ConsensusTopicID(topicNum=topic_id),
        # No limit, no end_time — stream stays open forever
    )
    for _ in stub.subscribeTopic(request):
        pass  # consume silently

stubs = []
for _ in range(200):  # 200 connections
    channel = grpc.insecure_channel("mirror-node:5600")
    stub = ConsensusServiceStub(channel)
    stubs.append(stub)
    for _ in range(5):  # 5 streams per connection = 1000 total
        threading.Thread(target=open_indefinite_stream, args=(stub, 1234), daemon=True).start()

# After ~1000 streams: file descriptor exhaustion, new subscribers get UNAVAILABLE
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L52-55)
```java
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-26)
```java
    private Long endTime;

    @Min(0)
    private long limit;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/CompositeTopicListener.java (L35-44)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        if (!listenerProperties.isEnabled()) {
            return Flux.empty();
        }

        return getTopicListener()
                .listen(filter)
                .filter(t -> filterMessage(t, filter))
                .doOnNext(this::recordMetric);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L17-43)
```java
public class ListenerProperties {

    private boolean enabled = true;

    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;

    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```
