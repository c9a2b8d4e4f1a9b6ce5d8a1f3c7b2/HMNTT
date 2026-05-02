### Title
Unbounded Concurrent `subscribeTopic` Streams Exhaust Shared `boundedElastic()` Scheduler in `PollingTopicListener`, Causing Severe Polling Delays for All Subscribers

### Summary
When `hiero.mirror.grpc.listener.type` is set to `POLL`, each `subscribeTopic` gRPC call invokes `PollingTopicListener.listen()`, which creates a new `PollingContext` and schedules an infinite repeat loop (`RepeatSpec.times(Long.MAX_VALUE)`) on the application-wide shared `Schedulers.boundedElastic()` singleton. Because there is no global cap on concurrent subscriptions and `maxConcurrentCallsPerConnection` only limits streams per TCP connection, an unauthenticated attacker can open arbitrarily many connections and saturate the bounded thread pool, causing all polling cycles to queue up and be delayed well beyond the 500ms interval.

### Finding Description

**Code path:**

`PollingTopicListener.java`, `listen()`, lines 34–49: [1](#0-0) 

- Line 31 assigns `Schedulers.boundedElastic()` — this is the **application-wide singleton** shared by `SharedPollingTopicListener`, `SharedTopicListener`, `TopicMessageServiceImpl`, and `PollingTopicMessageRetriever`.
- Lines 38–43: every `listen()` call schedules an infinite repeat loop on that shared scheduler. The `withFixedDelay(interval).withScheduler(scheduler)` uses the scheduler for timing, but the actual `poll()` work (lines 51–62) runs a synchronous JDBC call (`Flux.fromStream(topicMessageRepository.findByFilter(...))`) that **holds a worker thread** for the full duration of the DB query.
- `poll()` at line 61 calls `topicMessageRepository.findByFilter(newFilter)` — a blocking stream that occupies a `boundedElastic` worker thread until the query completes. [2](#0-1) 

**Root cause:** `BoundedElasticScheduler` defaults to `10 × CPU_count` worker threads (e.g., 40 on a 4-core host). With N concurrent subscribers, N DB queries run simultaneously every 500ms. Once N exceeds the thread cap, tasks queue up. The queue is 100,000 tasks deep — tasks do not get rejected, they simply wait, causing each subscriber's next poll to be delayed by however long the queue drains.

**Why the existing check is insufficient:**

`maxConcurrentCallsPerConnection = 5` (default) limits streams per TCP connection: [3](#0-2) [4](#0-3) 

There is no limit on the number of TCP connections, no global subscriber cap, and no authentication on `subscribeTopic`. The `subscriberCount` in `TopicMessageServiceImpl` is a metrics gauge only — it is never checked against a maximum. [5](#0-4) 

### Impact Explanation

With the thread pool saturated, every subscriber's polling cycle is delayed proportionally to queue depth. With 500 concurrent attacker streams on a 4-core host (40 threads), legitimate subscribers experience polling delays of `(500 / 40) × query_time` per cycle — easily 10–25× the 500ms interval (1000–2500% of baseline). Because the shared `Schedulers.boundedElastic()` singleton is also used by `SharedTopicListener.publishOn()`, `TopicMessageServiceImpl`'s safety-check flux, and `NetworkServiceImpl`, the starvation cascades across the entire gRPC application, not just the POLL listener. Topic message delivery to all subscribers is effectively frozen for the duration of the attack.

### Likelihood Explanation

The `subscribeTopic` RPC requires no authentication and is publicly reachable on port 5600. An attacker needs only a standard gRPC client (e.g., `grpcurl`) and the ability to open many TCP connections — a trivial capability from any host with outbound connectivity. The attack is repeatable and self-sustaining: streams stay open indefinitely (no server-side timeout on live subscriptions), so the attacker does not need to continuously reconnect. The only prerequisite is that the operator has set `listener.type = POLL`; while this is non-default, it is a documented and supported configuration.

### Recommendation

1. **Enforce a global concurrent-subscriber limit** in `TopicMessageServiceImpl.subscribeTopic()`: check `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` if exceeded.
2. **Isolate the polling scheduler**: replace `Schedulers.boundedElastic()` in `PollingTopicListener` with a dedicated, size-bounded `Schedulers.newBoundedElastic(cap, ...)` instance so attacker-induced saturation cannot spill into other application components.
3. **Add a global connection limit** to the Netty server builder (e.g., `serverBuilder.maxConnectionAge(...)` and a total-connection cap via a `ServerInterceptor` or infrastructure-level rate limiter).
4. **Consider making `poll()` non-blocking** by switching `topicMessageRepository.findByFilter` to a reactive R2DBC query, eliminating the thread-hold entirely.

### Proof of Concept

**Preconditions:** Server configured with `hiero.mirror.grpc.listener.type: POLL`. A valid topic ID exists (or `checkTopicExists: false`).

```bash
# Step 1: Open 200 TCP connections × 5 streams each = 1000 concurrent subscriptions
# Using grpcurl in background loops:
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1001}}' \
      <host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Step 2: Open a legitimate subscriber and measure polling latency
time grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 1001}, "limit": 1}' \
  <host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Expected result (baseline, no attack):** First message delivered within ~500–1000ms.

**Expected result (under attack):** First message delivery delayed by several seconds to minutes as the `boundedElastic` thread pool is saturated with 1000 concurrent DB-query tasks, each holding a worker thread. Server logs will show `Starting to poll every 500ms` for each attacker stream, and the `boundedElastic` queue depth will grow continuously.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-49)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-15)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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
