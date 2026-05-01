### Title
Unbounded Concurrent Throttled Subscriptions Exhaust Shared `boundedElastic()` Scheduler Pool

### Summary
`PollingTopicMessageRetriever.retrieve()` unconditionally sets `numRepeats = Long.MAX_VALUE` for every `throttled=true` subscription and schedules all repeat-delay tasks on a single shared `Schedulers.boundedElastic()` instance. Because the only per-connection cap (`maxConcurrentCallsPerConnection = 5`) is not a global cap, an unprivileged attacker who opens many TCP connections can accumulate arbitrarily many long-lived polling tasks on the shared scheduler, starving legitimate subscribers' historical-retrieval and safety-check work.

### Finding Description

**Exact code path:**

`PollingTopicMessageRetriever` constructor (line 41) creates the scheduler:
```java
scheduler = Schedulers.boundedElastic();   // global singleton, default cap = 10×CPUs threads, 100 000 queued tasks
```

`retrieve()` (lines 51–55) wires every subscription's repeat-delay onto that scheduler:
```java
return Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
        .withFixedDelay(context.getFrequency())
        .withScheduler(scheduler))          // ← all delay tasks land here
```

`PollingContext` constructor (lines 98–101) sets `numRepeats` for the throttled path:
```java
if (throttled) {
    numRepeats = Long.MAX_VALUE;            // ← effectively infinite
    frequency = retrieverProperties.getPollingFrequency();   // default 2 s
    maxPageSize = retrieverProperties.getMaxPageSize();      // default 1 000
}
```

`isComplete()` for the throttled path (lines 124–125):
```java
if (throttled) {
    return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
}
```
`pageSize` is reset to 0 before every poll (line 73). A topic with ≥ 1 000 messages per page keeps `isComplete()` returning `false` indefinitely, so the `Long.MAX_VALUE` repeat budget is never consumed.

`TopicMessageServiceImpl.subscribeTopic()` also schedules its safety-check on the same pool (line 70):
```java
.subscribeOn(Schedulers.boundedElastic());
```

**Root cause / failed assumption:** The design assumes that the per-connection gRPC call limit (`maxConcurrentCallsPerConnection = 5`, `NettyProperties` line 14, applied in `GrpcConfiguration` line 33) is sufficient to bound total scheduler load. It is not: it limits calls *per TCP connection*, not globally. An attacker who opens *C* connections can hold *5C* concurrent subscriptions, each contributing one queued delay-task to the shared scheduler every 2 seconds.

**Exploit flow:**
1. Attacker identifies (or creates) a topic with ≥ 1 000 historical messages so that every throttled poll returns a full page and `isComplete()` stays `false`.
2. Attacker opens *C* TCP connections to port 5600 and issues 5 `subscribeTopic` RPCs per connection, each with `consensusStartTime = 0` and no limit.
3. Each subscription enters the throttled historical-retrieval loop: poll → 2 s delay on `boundedElastic()` → poll → …
4. With *C* = 20 000 connections (feasible from a botnet or multiple IPs), 100 000 delay tasks fill the scheduler queue; Reactor begins rejecting new tasks with `RejectedExecutionException`.
5. New legitimate subscribers' `retrieve(filter, true)` and `safetyCheck` work cannot be scheduled; their streams stall or error.

### Impact Explanation
The `Schedulers.boundedElastic()` pool is shared across all historical-retrieval polling and safety-check work for every subscriber on the node. Saturating its task queue (default 100 000 entries) causes `RejectedExecutionException` for any new subscription attempt, effectively denying service to all new topic-message subscribers. Existing live-listener streams are unaffected, but any subscriber that needs historical catch-up (i.e., `startTime` in the past) is blocked. This constitutes a complete denial of the HCS subscription service for new clients.

### Likelihood Explanation
The attack requires no credentials — the gRPC `subscribeTopic` endpoint is unauthenticated. The only barrier is the per-connection call limit of 5, which is trivially bypassed by opening more connections. A single machine with a high file-descriptor limit can sustain thousands of TCP connections; a small botnet makes the 20 000-connection threshold easily reachable. The attack is repeatable and self-sustaining as long as the attacker keeps connections open.

### Recommendation
1. **Add a global concurrent-subscription cap** in `TopicMessageServiceImpl` using the existing `subscriberCount` `AtomicLong` (already tracked at lines 89–90): reject new subscriptions when the count exceeds a configurable threshold.
2. **Add a per-source-IP subscription limit** at the gRPC interceptor layer.
3. **Use a dedicated, bounded scheduler** for `PollingTopicMessageRetriever` (e.g., `Schedulers.newBoundedElastic(...)` with an explicit thread and queue cap) rather than the global singleton, so retriever exhaustion cannot affect other reactor work.
4. **Cap `numRepeats` for throttled subscriptions** to a finite value tied to a maximum subscription duration, rather than `Long.MAX_VALUE`.
5. **Enforce a global retriever timeout** (wall-clock, not idle-emission) so long-running historical retrievals are unconditionally terminated.

### Proof of Concept
```bash
# Requires grpcurl and a topic with >= 1000 messages (topic 0.0.12345)
# Open 5 subscriptions per connection across 200 parallel processes
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID":{"topicNum":12345},"consensusStartTime":{"seconds":0},"limit":0}' \
      mirror-node:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait

# After ~1000 connections are open, attempt a new legitimate subscription:
grpcurl -plaintext \
  -d '{"topicID":{"topicNum":12345},"consensusStartTime":{"seconds":0},"limit":1}' \
  mirror-node:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
# Expected: RejectedExecutionException / stream never starts
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-101)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```
