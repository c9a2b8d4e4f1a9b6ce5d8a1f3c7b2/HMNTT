### Title
Unbounded gRPC Subscriber Exhaustion of `boundedElastic` Scheduler Threads in `subscribeTopic()`

### Summary
`TopicMessageServiceImpl.subscribeTopic()` accepts unlimited concurrent subscriptions from any unauthenticated caller with no enforcement of a maximum subscriber count. Each active subscription with no `endTime` permanently occupies a thread in the `Schedulers.boundedElastic()` pool via `SharedTopicListener.publishOn(Schedulers.boundedElastic())`. An attacker opening enough TCP connections (each carrying 5 calls, the per-connection maximum) can exhaust the bounded elastic thread pool, stalling all legitimate message delivery pipelines.

### Finding Description

**Exact code path:**

`subscribeTopic()` increments `subscriberCount` as a pure metric with no enforcement gate: [1](#0-0) [2](#0-1) 

When `endTime` is null, `pastEndTime()` returns `Flux.never()`, making the subscription permanent: [3](#0-2) 

`isComplete()` always returns `false` when `endTime` is null: [4](#0-3) 

Each subscription's live message path calls `topicListener.listen()`, which in `SharedTopicListener` calls `publishOn(Schedulers.boundedElastic())` **per subscriber**: [5](#0-4) 

Additionally, the safety check in every subscription also schedules on `boundedElastic()`: [6](#0-5) 

`PollingTopicListener` creates its own `Schedulers.boundedElastic()` instance per-listener and schedules all polling on it: [7](#0-6) 

**The only connection-level mitigation** is `maxConcurrentCallsPerConnection = 5`, applied in `GrpcConfiguration`: [8](#0-7) [9](#0-8) 

No `maxConnections`, `maxConnectionAge`, `maxConnectionIdle`, or IP-rate-limit is configured anywhere in `GrpcConfiguration`. No authentication is required on the gRPC endpoint.

**Root cause:** `subscriberCount` is a monitoring gauge only — it is never compared against a maximum before accepting a new subscription. The Netty server has no total connection limit. The `boundedElastic` scheduler has a hard thread cap of `10 × availableProcessors()` (e.g., 100 threads on a 10-core host). Each active subscriber holds one of those threads via `publishOn(Schedulers.boundedElastic())` for the lifetime of the subscription.

### Impact Explanation

Once the bounded elastic thread pool is saturated, all `publishOn(Schedulers.boundedElastic())` calls queue or are rejected. This stalls message delivery for every legitimate subscriber — both the `SharedTopicListener` path (Redis/SharedPoll) and the safety-check path. The gRPC service becomes unresponsive to all topic message streaming. The `maxBufferSize = 16384` overflow strategy is `ERROR`, so backpressure-overflowed subscribers are terminated with errors, compounding the degradation. [10](#0-9) 

### Likelihood Explanation

No authentication or account is required — any host that can reach TCP port 5600 can exploit this. The attacker needs only `ceil(threadPoolSize / 5)` TCP connections (e.g., 20 connections on a 10-core host) to saturate the pool. Opening 20 long-lived TCP connections with 5 gRPC streaming calls each is trivially achievable with `grpcurl`, any gRPC client library, or a simple script. The attack is repeatable and persistent as long as the attacker holds the connections open.

### Recommendation

1. **Enforce a total subscriber cap** inside `subscribeTopic()` — check `subscriberCount` against a configurable `maxSubscribers` property and return an error if exceeded, before constructing any `TopicContext` or Flux.
2. **Add a Netty connection limit** in `GrpcConfiguration` via `serverBuilder.maxConnectionAge(...)` / `serverBuilder.maxConnectionIdle(...)` and a total connection count limit.
3. **Add per-IP rate limiting** at the ingress/load-balancer layer (the Helm chart's `maxRatePerEndpoint: 250` only applies to GCP Gateway, not direct access).
4. **Require a `limit` or `endTime`** on subscriptions, or enforce a server-side maximum subscription duration. [11](#0-10) 

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, server at localhost:5600, topic 0.0.41110 exists

# Step 1: Open 20 connections × 5 concurrent streaming calls = 100 permanent subscriptions
# (adjust N_CONNECTIONS based on server CPU count: ceil(10*nCPU / 5))

for i in $(seq 1 20); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Step 2: Observe that legitimate subscribers now receive no messages
# (boundedElastic pool exhausted; publishOn queues stall)
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}}' \
  localhost:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: hangs indefinitely with no messages delivered

# Step 3: Confirm via metrics
curl http://localhost:8081/actuator/metrics/hiero.mirror.grpc.subscribers
# subscriberCount will show 100+ with 0 messages/s throughput
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-126)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-206)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-43)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L27-35)
```java
    @Bean
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
