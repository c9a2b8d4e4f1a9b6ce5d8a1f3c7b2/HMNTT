### Title
Unbounded Concurrent Subscription DoS via Unlimited TCP Connections to `TopicMessageRetriever`

### Summary
The `TopicMessageRetriever.retrieve()` interface and its `PollingTopicMessageRetriever` implementation impose no global or per-IP limit on concurrent subscriptions. The only guard — `maxConcurrentCallsPerConnection = 5` — is scoped to a single TCP connection, not to a client identity or IP address. An unauthenticated attacker can open an arbitrary number of TCP connections, each carrying 5 concurrent `subscribeTopic` streams, causing unbounded database polling that exhausts server resources and denies service to legitimate users.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` (line 43) calls `topicMessageService.subscribeTopic(filter)` with no caller identity or rate-limit check. [1](#0-0) 

`TopicMessageServiceImpl.subscribeTopic()` tracks a global `subscriberCount` (line 48) but this is a **Micrometer gauge metric only** — it is never compared against any maximum and never used to reject new subscriptions. [2](#0-1) 

The counter is incremented on subscribe and decremented on completion, but no guard exists between those two events: [3](#0-2) 

Each accepted subscription calls `topicMessageRetriever.retrieve(filter, true)`, which in `PollingTopicMessageRetriever` creates an independent cold `Flux` that polls the database every 2 seconds (`pollingFrequency = 2s`) with up to 1000 rows per page, indefinitely (throttled path sets `numRepeats = Long.MAX_VALUE`): [4](#0-3) [5](#0-4) 

Additionally, each subscription spawns a 1-second safety-check that issues a second independent DB query: [6](#0-5) 

**The only existing guard** is `maxConcurrentCallsPerConnection = 5` in `NettyProperties`, applied in `GrpcConfiguration`: [7](#0-6) [8](#0-7) 

This is a Netty-level per-TCP-connection limit. gRPC over HTTP/2 allows a client to open an unlimited number of TCP connections from the same IP. There is no per-IP connection limit, no global subscription cap, and no authentication requirement anywhere in the gRPC stack. [9](#0-8) 

### Impact Explanation

Each subscription independently polls the database every 2 seconds. With N TCP connections × 5 streams each, an attacker sustains `5N` concurrent DB polling loops. At N=200 connections (5000 ms to establish on a single host), the server sustains 2500 DB queries/second from one attacker alone, exhausting the database connection pool and starving legitimate subscribers. The `TopicMessageFilter` requires no authentication and accepts any valid `topicId`, which is publicly enumerable from the REST API. The service has no timeout on open-ended subscriptions (no `endTime` set), so each stream persists indefinitely. [10](#0-9) 

### Likelihood Explanation

No privileges, credentials, or special knowledge are required. The gRPC port (5600) is publicly exposed. A single attacker machine can open hundreds of TCP connections using standard gRPC client libraries (e.g., `grpc-java`, `grpcurl`). The attack is repeatable, scriptable, and requires no state. The `subscriberCount` metric will alert operators only after the damage is done, with no automatic mitigation. [2](#0-1) 

### Recommendation

1. **Enforce a global subscription ceiling**: Add a configurable `maxSubscribers` property to `GrpcProperties`. In `TopicMessageServiceImpl.subscribeTopic()`, check `subscriberCount.get() >= maxSubscribers` before accepting a new subscription and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Add per-IP connection limiting**: Configure Netty's `maxConnectionsPerIp` or deploy an L4/L7 proxy (e.g., Envoy) with per-source-IP connection and RPS limits in front of port 5600.
3. **Require a mandatory `endTime` or enforce a maximum subscription duration**: Prevent indefinite open-ended subscriptions by capping the maximum allowed subscription window.
4. **Rate-limit `subscribeTopic` calls per IP**: Implement a token-bucket interceptor at the gRPC server interceptor layer.

### Proof of Concept

```bash
# Install grpcurl. Repeat the following in a loop to open many connections:
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}, "consensusStartTime": {"seconds": 0}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
# 1000 concurrent subscriptions, each polling the DB every 2s = 500 DB queries/sec from one host.
# Scale to multiple hosts or increase loop count to exhaust DB connection pool.
```

Each background process holds an open gRPC stream on a separate TCP connection, bypassing the `maxConcurrentCallsPerConnection = 5` per-connection guard. The `subscriberCount` metric will climb without bound and no rejection occurs.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L43-48)
```java
    public void subscribeTopic(ConsensusTopicQuery request, StreamObserver<ConsensusTopicResponse> responseObserver) {
        final var disposable = Mono.fromCallable(() -> toFilter(request))
                .flatMapMany(topicMessageService::subscribeTopic)
                .map(this::toResponse)
                .onErrorMap(ProtoUtil::toStatusRuntimeException)
                .subscribe(responseObserver::onNext, responseObserver::onError, responseObserver::onCompleted);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L66-70)
```java
        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-108)
```java
        private PollingContext(TopicMessageFilter filter, boolean throttled) {
            this.filter = filter;
            this.throttled = throttled;

            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-30)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L22-28)
```java
    private int maxPageSize = 1000;

    @NotNull
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
