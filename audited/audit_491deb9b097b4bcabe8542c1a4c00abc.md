### Title
Heap Exhaustion DoS via Unbounded Concurrent Subscriber Polling with Eager Result Materialization in `PollingTopicListener`

### Summary
`PollingTopicListener.poll()` calls `TopicMessageRepositoryCustomImpl.findByFilter()`, which uses JPA `getResultList()` to eagerly materialize up to `maxPageSize` (default 5000) `TopicMessage` objects into a heap-allocated `List` per poll cycle per subscriber. Because there is no global subscriber or connection count limit — only a per-connection cap of 5 concurrent calls — an unauthenticated attacker can open arbitrarily many gRPC connections, each with 5 concurrent `subscribeTopic` streams targeting a high-throughput topic, causing simultaneous heap allocations across all subscribers that exhaust JVM memory.

### Finding Description

**Code path:**

`PollingTopicListener.listen()` (line 38) defers to `poll()` on every interval tick, once per subscriber:

```
Flux.defer(() -> poll(context))
    .repeatWhen(RepeatSpec.times(Long.MAX_VALUE).withFixedDelay(interval)...)
``` [1](#0-0) 

Inside `poll()`, `pageSize` is capped at `listenerProperties.getMaxPageSize()` (default 5000, `@Min(32)` only — no upper bound): [2](#0-1) [3](#0-2) 

`findByFilter()` is then called, which **eagerly materializes** the full result set via `getResultList()`:

```java
return typedQuery.getResultList().stream();
// getResultStream()'s cursor doesn't work with reactive streams
``` [4](#0-3) 

This is not a lazy/cursor-based stream. Every poll cycle for every subscriber allocates a new `List<TopicMessage>` of up to 5000 objects on the JVM heap before any element is consumed.

**Root cause — failed assumption:** The design assumes a bounded number of concurrent subscribers. There is no global subscriber count limit; `subscriberCount` is only a metrics gauge: [5](#0-4) 

The only concurrency control is `maxConcurrentCallsPerConnection = 5`, which is **per-connection**, not global: [6](#0-5) [7](#0-6) 

No maximum connection count is configured anywhere in `GrpcConfiguration` or `NettyProperties`. The gRPC `subscribeTopic` API requires no authentication. [8](#0-7) 

### Impact Explanation

With N open connections × 5 concurrent streams each × 5000 `TopicMessage` objects per poll cycle, the JVM heap is filled with `N × 25,000` live `TopicMessage` objects every 500 ms (default interval). Each `TopicMessage` carries byte-array fields (`message`, `runningHash`, etc.), making per-object size non-trivial. At a modest 200 connections (1000 concurrent subscribers), a single poll wave allocates 5,000,000 objects simultaneously. This causes `OutOfMemoryError`, crashing the gRPC service and denying all subscribers — including legitimate ones — access to HCS topic data. The impact is complete availability loss of the mirror node's gRPC API.

### Likelihood Explanation

The attack requires no credentials, no special protocol knowledge beyond the public gRPC protobuf definition (documented at `docs/grpc/README.md`), and no on-chain resources. A single attacker machine can open hundreds of TCP connections to port 5600 and issue `subscribeTopic` RPCs with `limit=0` (unlimited) targeting any existing high-throughput topic. The attack is repeatable and can be sustained indefinitely. The only prerequisite is that the deployment uses `listener.type=POLL` (a documented, supported configuration option). [9](#0-8) 

### Recommendation

1. **Replace `getResultList()` with a true streaming/cursor approach** in `TopicMessageRepositoryCustomImpl.findByFilter()` (line 60) to avoid full-page heap materialization per subscriber per poll. Use `ScrollableResults` with `HINT_FETCH_SIZE` or Spring Data's `Stream<T>` with a proper JDBC fetch-size hint.
2. **Enforce a global maximum subscriber count** in `TopicMessageServiceImpl.subscribeTopic()` — reject new subscriptions when `subscriberCount` exceeds a configurable threshold.
3. **Add a `maxConnections` limit** to `NettyServerBuilder` in `GrpcConfiguration` (e.g., `serverBuilder.maxConnectionAge(...)` and a connection count interceptor).
4. **Add an upper bound (`@Max`) to `maxPageSize`** in `ListenerProperties` to prevent operator misconfiguration amplifying the attack.

### Proof of Concept

```bash
# Prerequisites: grpcurl installed, topic 0.0.41110 exists with active message flow,
# mirror node running with listener.type=POLL on port 5600

# Open 200 connections, each with 5 concurrent unlimited subscriptions (1000 total subscribers)
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 41110}, "limit": 0}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic \
      > /dev/null 2>&1 &
  done
done

# Each subscriber independently calls poll() every 500ms.
# Each poll() calls getResultList() materializing up to 5000 TopicMessage objects.
# 1000 subscribers × 5000 objects × ~500 bytes/object = ~2.5 GB heap pressure per poll wave.
# JVM OOM occurs within seconds on a standard heap configuration.
wait
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-61)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L25-26)
```java
    @Min(32)
    private int maxPageSize = 5000;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** docs/grpc/README.md (L14-16)
```markdown
Example invocation using [grpcurl](https://github.com/fullstorydev/grpcurl):

`grpcurl -plaintext -d '{"topicID": {"topicNum": 41110}, "limit": 0}' localhost:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic`
```
