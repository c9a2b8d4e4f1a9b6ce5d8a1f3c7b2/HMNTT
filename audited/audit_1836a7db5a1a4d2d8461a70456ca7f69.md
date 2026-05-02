### Title
Unbounded Concurrent Subscriptions Exhaust Shared `boundedElastic` Scheduler via Indefinite Throttled Polling

### Summary
`PollingTopicMessageRetriever.retrieve()` sets `numRepeats = Long.MAX_VALUE` for every throttled subscription and schedules all repeat iterations on a single shared `Schedulers.boundedElastic()` instance. Because `TopicMessageServiceImpl` tracks subscriber count only as a metric gauge with no enforcement ceiling, an unprivileged attacker can open unlimited gRPC connections (each with up to 5 concurrent calls per `maxConcurrentCallsPerConnection`) and flood the shared scheduler, starving legitimate subscriptions and new connection processing.

### Finding Description

**Code path:**

`ConsensusController.subscribeTopic()` → `TopicMessageServiceImpl.subscribeTopic()` → `topicMessageRetriever.retrieve(filter, true)` → `PollingTopicMessageRetriever.retrieve()`

In `PollingTopicMessageRetriever`:

```java
// Line 41 — single shared scheduler for ALL subscriptions
scheduler = Schedulers.boundedElastic();

// Lines 51-55 — every throttled subscription schedules on this shared scheduler
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .jitter(0.1)
        .withFixedDelay(context.getFrequency())
        .withScheduler(scheduler))   // ← shared scheduler
```

```java
// Lines 98-99 — throttled path sets numRepeats to Long.MAX_VALUE
if (throttled) {
    numRepeats = Long.MAX_VALUE;
```

`isComplete()` (lines 121-128) only terminates the loop when the last DB page is smaller than `maxPageSize`. With `startTime=0` and a large topic history, each subscription holds the scheduler busy for the entire drain duration (up to `timeout=60s`). After the historical phase, `TopicMessageServiceImpl` also schedules a `safetyCheck` on `Schedulers.boundedElastic()` (line 70) per subscription.

**No subscriber cap is enforced:**

```java
// TopicMessageServiceImpl lines 48, 89-90 — counter is a metric only, never checked
private final AtomicLong subscriberCount = new AtomicLong(0L);
...
.doOnSubscribe(s -> subscriberCount.incrementAndGet())
.doFinally(s -> subscriberCount.decrementAndGet())
```

**Per-connection limit does not bound total subscriptions:**

```java
// NettyProperties line 14 — limits calls per connection, not total connections
private int maxConcurrentCallsPerConnection = 5;
```

An attacker opens N TCP connections × 5 calls = 5N concurrent subscriptions, all sharing the single `boundedElastic` scheduler in `PollingTopicMessageRetriever`.

**`retryWhen` prevents self-termination on errors:**

```java
// Line 58 — DB errors cause indefinite retry on the same scheduler
.retryWhen(Retry.backoff(Long.MAX_VALUE, Duration.ofSeconds(1)))
```

### Impact Explanation
Reactor's `boundedElastic` scheduler caps threads at `10 × availableProcessors` (default max 200). Each subscription schedules a DB poll task every `pollingFrequency=2s`. With thousands of subscriptions, the scheduler's thread pool saturates; new tasks queue up (100 000-task-per-thread limit). Once the queue fills, `RejectedExecutionException` is thrown, causing all new subscription processing — including legitimate users — to fail. The gRPC Netty layer itself uses `applicationTaskExecutor` (line 32 of `GrpcConfiguration`), but the reactive pipeline stalls because the `boundedElastic` scheduler that drives the `RepeatSpec` delays is exhausted. This is a full service-level DoS with no funds at direct risk, matching the stated Medium scope.

### Likelihood Explanation
No authentication is required to call `subscribeTopic`. The attacker needs only a valid `topicId` (publicly known on mainnet/testnet) and the ability to open many TCP connections. Standard tools (`grpcurl`, custom gRPC clients) can open hundreds of connections in parallel. The attack is repeatable and self-sustaining because `retryWhen(Retry.backoff(Long.MAX_VALUE, ...))` keeps failed subscriptions alive on the scheduler.

### Recommendation
1. **Enforce a global subscriber cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable `maxSubscribers` property, returning `RESOURCE_EXHAUSTED` to the caller.
2. **Add a per-IP or per-connection subscription limit** at the Netty layer or in `ConsensusController`.
3. **Use a dedicated, bounded scheduler per subscription** (or a fixed-size thread pool) rather than a single shared `boundedElastic` instance, so one subscriber class cannot monopolize the pool.
4. **Cap `numRepeats`** in the throttled path to a finite value tied to `timeout / pollingFrequency` rather than `Long.MAX_VALUE`.
5. **Add a `maxSubscribers` configuration property** to `RetrieverProperties` and check it before creating the `PollingContext`.

### Proof of Concept

```
# Prerequisites: valid topicId on a mirror node with historical messages
# Tool: grpcurl or any gRPC client

# Step 1: Open 200 TCP connections, each with 5 concurrent subscribeTopic calls
# (1000 total subscriptions), all with startTime=0 and no limit/endTime

for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext -d '{
      "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1234},
      "consensusStartTime": {"seconds": 0, "nanos": 0}
    }' <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Step 2: Observe — new subscribeTopic calls begin failing or hanging
# The shared boundedElastic scheduler in PollingTopicMessageRetriever is saturated
# hiero_mirror_grpc_subscribers metric climbs without bound
# DB connection pool (hikaricp_connections_active) pegs at max
# Legitimate subscribers receive no messages or connection errors
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L51-55)
```java
        return Flux.defer(() -> poll(context))
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L94-107)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-128)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L87-91)
```java
        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
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
