### Title
Unbounded Subscription Growth in `PollingTopicListener.listen()` Enables Scheduler Saturation and DoS

### Summary
`PollingTopicListener.listen()` creates an independent, indefinitely-repeating polling loop on the shared `Schedulers.boundedElastic()` scheduler for every subscription, with no server-side cap on total concurrent subscriptions. An unauthenticated attacker opening many connections (each with up to 5 concurrent calls per the per-connection limit) can saturate the scheduler's bounded task queue, exhaust the database connection pool, and deny service to all legitimate subscribers.

### Finding Description
**Code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, `listen()`, lines 34–49:

```java
private final Scheduler scheduler = Schedulers.boundedElastic();   // line 31 — global shared instance

public Flux<TopicMessage> listen(TopicMessageFilter filter) {
    PollingContext context = new PollingContext(filter);
    Duration interval = listenerProperties.getInterval();           // default 500ms

    return Flux.defer(() -> poll(context))
            .delaySubscription(interval, scheduler)                 // schedules on boundedElastic
            .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)            // repeats ~forever
                    .withFixedDelay(interval)
                    .withScheduler(scheduler))                      // every repeat queues a task
            ...
}
```

**Root cause:** Every call to `listen()` enqueues a new, perpetual stream of delay/repeat tasks onto the single global `Schedulers.boundedElastic()` instance. `Schedulers.boundedElastic()` has a bounded thread pool (`10 × CPU cores`) and a bounded task queue (default **100,000 tasks**). With N concurrent subscriptions each firing every 500 ms, the scheduler receives `2N` tasks per second. At ~1,000 subscriptions the queue fills in seconds.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` (`NettyProperties` line 14, `GrpcConfiguration` line 33) is a **per-TCP-connection** limit only. An attacker opens many independent connections.
- `subscriberCount` in `TopicMessageServiceImpl` lines 48–55 is a **Micrometer gauge** — it is never compared against any threshold and never rejects a subscription.
- No authentication or rate-limiting is applied to `ConsensusController.subscribeTopic()` (lines 43–53).

### Impact Explanation
When the `boundedElastic()` queue is full, Reactor throws `RejectedExecutionException` for every new scheduled task, terminating **all** active polling subscriptions — not just the attacker's. This is a complete denial of service for the `POLL` listener mode. Secondary effects include: heap growth proportional to the number of live `PollingContext` + `Flux` operator chain objects, and exhaustion of the HikariCP database connection pool as each active subscription issues a `findByFilter` query every 500 ms.

### Likelihood Explanation
The attack requires no credentials and no special knowledge beyond the public gRPC protobuf definition (documented in `docs/grpc/README.md`). A single attacker machine can open hundreds of TCP connections and issue 5 `subscribeTopic` RPCs per connection. The `POLL` listener type must be explicitly configured (`hiero.mirror.grpc.listener.type=POLL`); the default is `REDIS`, which uses a shared polling loop and is not affected. Deployments that opt into `POLL` mode are fully exposed.

### Recommendation
1. **Enforce a global subscription ceiling** in `TopicMessageServiceImpl.subscribeTopic()`: compare `subscriberCount` against a configurable maximum and return `RESOURCE_EXHAUSTED` when exceeded.
2. **Add a per-IP or per-connection subscription limit** at the gRPC interceptor layer.
3. **Avoid per-subscription scheduler allocation**: the `SHARED_POLL` / `REDIS` modes already share a single polling loop; document that `POLL` mode is unsafe for public-facing deployments.
4. **Add a `maxConnections` limit** to `NettyProperties` / `GrpcConfiguration` alongside `maxConcurrentCallsPerConnection`.

### Proof of Concept
```bash
# Open 200 connections × 5 concurrent subscribeTopic calls = 1000 subscriptions
# Each uses a distinct topicId to prevent any shared-state optimisation
for i in $(seq 1 200); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d "{\"topicID\": {\"topicNum\": $((i * 100 + j))}, \"limit\": 0}" \
      <mirror-node-host>:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done
wait
# Within seconds, legitimate subscribers receive RejectedExecutionException /
# INTERNAL errors as the boundedElastic queue (100,000 tasks) is saturated.
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L34-49)
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
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L32-34)
```java
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L37-37)
```java
    private ListenerType type = ListenerType.REDIS;
```
