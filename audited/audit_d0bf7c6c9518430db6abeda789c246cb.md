### Title
Unbounded Concurrent Subscriptions Exhaust Global `boundedElastic` Thread Pool via safetyCheck-Triggered Blocking DB Polls

### Summary
`TopicMessageServiceImpl.subscribeTopic()` creates a per-subscription `safetyCheck` Flux that fires after 1 second and calls `topicMessageRetriever.retrieve(gapFilter, false)` (unthrottled mode). The `PollingTopicMessageRetriever` schedules all repeat DB polls via `withScheduler(Schedulers.boundedElastic())`, which is the **global singleton** bounded elastic pool — the same pool used by `subscribeOn(Schedulers.boundedElastic())` in the safetyCheck and by `PollingTopicListener`/`SharedPollingTopicListener`. Because there is no global subscription limit or rate limit on the gRPC endpoint, an unprivileged attacker can open enough concurrent subscriptions to saturate the bounded elastic pool with blocking JDBC calls, causing all other operations that depend on it to queue indefinitely.

### Finding Description

**Code path:**

`TopicMessageServiceImpl.subscribeTopic()` (lines 67–70): [1](#0-0) 

```java
Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
        .filter(_ -> !topicContext.isComplete())
        .flatMapMany(_ -> missingMessages(topicContext, null))
        .subscribeOn(Schedulers.boundedElastic());
```

After 1 second, `missingMessages(topicContext, null)` is called, which calls `topicMessageRetriever.retrieve(gapFilter, false)` (unthrottled): [2](#0-1) 

`PollingTopicMessageRetriever.retrieve()` (lines 51–55) uses `withScheduler(scheduler)` where `scheduler = Schedulers.boundedElastic()` (the global singleton): [3](#0-2) 

When the `repeatWhen` delay fires, the next `poll()` runs **on a bounded elastic thread** and executes a **blocking JDBC call**: [4](#0-3) 

In unthrottled mode, `numRepeats = unthrottled.getMaxPolls()` (default 12) at `pollingFrequency = 20ms`: [5](#0-4) 

**Root cause:** `Schedulers.boundedElastic()` is a JVM-global singleton. Every call to it — in `TopicMessageServiceImpl`, `PollingTopicMessageRetriever`, `PollingTopicListener`, and `SharedPollingTopicListener` — returns the **same pool**. The pool is capped at `10 × availableProcessors` threads. Each safetyCheck-triggered unthrottled retrieval schedules up to 12 blocking DB polls on this shared pool. With N concurrent subscriptions, N × 12 blocking tasks flood the pool simultaneously.

**Failed assumption:** The design assumes a bounded number of concurrent subscriptions. No enforcement exists — `subscriberCount` is a metric only: [6](#0-5) 

The only per-connection limit is `maxConcurrentCallsPerConnection = 5`, but there is no limit on the number of connections: [7](#0-6) 

### Impact Explanation
When the bounded elastic pool is saturated, all operations that depend on it stall: `PollingTopicListener` (per-subscriber polling), `SharedPollingTopicListener` (shared polling), `PollingTopicMessageRetriever` timeout scheduling, and the safetyCheck `subscribeOn` itself. Legitimate subscribers receive no messages and eventually time out. The server-side reactive pipeline for all topic subscriptions is effectively frozen for the duration of the attack. The database connection pool may also be exhausted as N × 12 concurrent JDBC queries are issued.

### Likelihood Explanation
No authentication or rate limiting is required. An attacker needs only a valid topic ID (publicly observable on-chain) and the ability to open many TCP connections to port 5600. Opening 200 connections × 5 calls = 1,000 concurrent subscriptions on a 4-core server (40 bounded elastic threads) means 12,000 blocking DB tasks queued in ~1 second. This is achievable with a single machine using standard gRPC client libraries. The attack is repeatable: subscriptions can be re-opened as fast as they time out.

### Recommendation
1. **Enforce a global subscription cap**: Check `subscriberCount` against a configurable maximum in `subscribeTopic()` and return an error if exceeded.
2. **Isolate the safetyCheck scheduler**: Use a dedicated, size-limited `Schedulers.newBoundedElastic(...)` instance for the safetyCheck rather than the global singleton, preventing cross-contamination with listener/retriever pools.
3. **Add per-IP or per-connection subscription rate limiting** at the gRPC layer, similar to the `ThrottleConfiguration` used in the web3 module.
4. **Use a non-blocking retriever** for the safetyCheck path, or wrap the blocking `Flux.fromStream(...)` call with an explicit `subscribeOn` on a dedicated scheduler with a bounded queue.

### Proof of Concept
```
Preconditions:
- Mirror node running with default config (4 CPUs → 40 bounded elastic threads)
- A valid topic ID with no recent messages (e.g., topic 0.0.1234)

Steps:
1. Open 200 gRPC connections to port 5600.
2. On each connection, open 5 concurrent ConsensusService/subscribeTopic streams
   with startTime = now, topicId = 0.0.1234 (no endTime, no limit).
   → 1,000 concurrent subscriptions active.
3. Wait 1 second.
   → All 1,000 safetyChecks fire simultaneously.
   → Each calls retrieve(gapFilter, false) → up to 12 polls × 20ms on boundedElastic.
   → 12,000 blocking JDBC tasks queued against a 40-thread pool.
4. Observe: legitimate subscribers on other topics receive no messages.
   PollingTopicListener stops polling (its scheduler tasks are queued behind the flood).
   Server logs show bounded elastic queue depth growing.
5. Attack is sustained by keeping the 1,000 connections open; each subscription
   re-triggers the safetyCheck if no messages arrive.
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L142-149)
```java
        if (current == null) {
            long startTime = last != null
                    ? last.getConsensusTimestamp() + 1
                    : topicContext.getFilter().getStartTime();
            var gapFilter =
                    topicContext.getFilter().toBuilder().startTime(startTime).build();
            log.info("Safety check triggering gap recovery query with filter {}", gapFilter);
            return topicMessageRetriever.retrieve(gapFilter, false);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L41-55)
```java
        scheduler = Schedulers.boundedElastic();
    }

    @Override
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-78)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L36-47)
```java
    public static class UnthrottledProperties {

        @Min(1000)
        private int maxPageSize = 5000;

        @Min(4)
        private long maxPolls = 12;

        @DurationMin(millis = 10)
        @NotNull
        private Duration pollingFrequency = Duration.ofMillis(20);
    }
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
