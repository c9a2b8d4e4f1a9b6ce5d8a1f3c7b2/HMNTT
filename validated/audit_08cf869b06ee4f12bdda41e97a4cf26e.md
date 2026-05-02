I verified the key claims against the actual source code. Here is my assessment:

**Verified facts:**
- `PollingTopicListener.listen()` does create a per-subscriber `Flux` with `RepeatSpec.times(Long.MAX_VALUE)` at 500ms intervals — confirmed. [1](#0-0) 
- `subscriberCount` in `TopicMessageServiceImpl` is wired only to a Micrometer `Gauge` — no enforcement gate exists. [2](#0-1) 
- `ListenerProperties` has no `maxSubscriptions`, `maxConnectionsPerIp`, or any subscriber-limiting field. [3](#0-2) 
- `GrpcConfiguration` does apply `maxConcurrentCallsPerConnection` from `NettyProperties`, providing some server-level control — but I was unable to read `NettyProperties.java` to confirm its default value. [4](#0-3) 
- **Critical context the claim omits:** The default `ListenerType` is `REDIS`, not `POLL`. [5](#0-4)  The `SHARED_POLL` type uses a single shared `Flux` with `.share()`, meaning all subscribers share one polling loop — this architectural pattern directly mitigates the per-subscriber DB amplification. [6](#0-5) 

The vulnerability is technically accurate and real, but only for deployments explicitly configured with `ListenerType.POLL`. The claim correctly scopes it to that mode in its impact section.

---

# Audit Report

## Title
Unbounded Per-Subscriber Database Polling in `PollingTopicListener.listen()` Enables Unauthenticated DoS via Subscription Flooding

## Summary
When `ListenerType.POLL` is configured, `PollingTopicListener.listen()` creates an independent, perpetual database polling loop for every subscriber with no cap on concurrent subscriptions, no per-IP limit, and no per-client connection limit. An unauthenticated attacker can open an arbitrarily large number of gRPC streams, each triggering its own ~500ms JDBC polling cycle, exhausting the DB connection pool.

## Finding Description

`PollingTopicListener.listen()` creates a new `PollingContext` per call and schedules an infinite `Flux.defer(() -> poll(context))` loop:

```java
return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))
``` [7](#0-6) 

Each `poll()` call executes a JDBC query via `topicMessageRepository.findByFilter(newFilter)` fetching up to `maxPageSize` (default 5000) rows: [8](#0-7) 

`TopicMessageServiceImpl` tracks `subscriberCount` via an `AtomicLong`, but this is wired exclusively to a Micrometer `Gauge` for observability. No maximum is checked and no subscription is ever rejected: [2](#0-1) 

`ListenerProperties` contains no `maxSubscriptions`, `maxConnectionsPerIp`, or any subscriber-limiting field: [3](#0-2) 

`GrpcConfiguration` applies `maxConcurrentCallsPerConnection` from `NettyProperties`, which provides a partial server-level control, but this limits streams per connection — an attacker can open multiple connections to bypass it: [4](#0-3) 

**Scope constraint:** The default `ListenerType` is `REDIS`, not `POLL`. This vulnerability is only exploitable when an operator has explicitly set `hiero.mirror.grpc.listener.type=POLL`. The `SHARED_POLL` type is not affected because it uses a single shared polling loop via `.share()` regardless of subscriber count. [6](#0-5) 

## Impact Explanation
With `POLL` mode active, every subscriber independently issues JDBC queries every ~500ms. With N=500 concurrent subscriptions, this produces ~1000 DB queries/second, each potentially returning up to 5000 rows. DB connection pool saturation blocks the importer's write path, preventing new HCS transactions from being persisted — a denial of service for transaction confirmation visibility. The load scales linearly with subscriber count with no diminishing returns until the pool is exhausted.

## Likelihood Explanation
The attack requires no credentials, no special protocol knowledge beyond standard gRPC, and no exploit code — only a gRPC client library (e.g., `grpcurl`, `ghz`, or any HCS SDK). It is trivially scriptable. The only practical barriers are: (1) the operator must have explicitly configured `POLL` mode (not the default), and (2) network bandwidth to sustain N open long-lived gRPC streams, which is negligible. Any public mirror node deployment with `POLL` mode configured is directly exposed.

## Recommendation
1. **Enforce a subscriber cap:** Add a `maxSubscribers` field to `ListenerProperties` and check it in `TopicMessageServiceImpl.subscribeTopic()` before incrementing `subscriberCount`, returning a `RESOURCE_EXHAUSTED` gRPC status when exceeded.
2. **Prefer `SHARED_POLL` or `REDIS`:** The `SHARED_POLL` listener already uses a single shared polling loop via `.share()` and is architecturally immune to this amplification. Operators should be strongly discouraged from using `POLL` mode in production; consider deprecating or removing it.
3. **Configure `maxConcurrentCallsPerConnection`:** Set an explicit, low value in `NettyProperties` to limit per-connection stream counts.
4. **Add per-IP connection limiting** at the load balancer or ingress layer for the gRPC port.

## Proof of Concept
```bash
# Open N concurrent gRPC subscriptions to a POLL-mode mirror node
# Each stream triggers an independent 500ms DB polling loop
for i in $(seq 1 500); do
  grpcurl -plaintext \
    -d '{"topicID": {"topicNum": 1}}' \
    <mirror-node-host>:5600 \
    com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
wait
# Result: ~1000 JDBC queries/second against the DB, pool exhaustion,
# importer write path starved of connections.
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L17-43)
```java
public class ListenerProperties {

    private boolean enabled = true;

    @Min(8192)
    @Max(65536)
    private int maxBufferSize = 16384;

    @Min(32)
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);

    @Min(4)
    @Max(256)
    private int prefetch = 48;

    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedPollingTopicListener.java (L41-52)
```java
        topicMessages = Flux.defer(() -> poll(context).subscribeOn(scheduler))
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
                .name(METRIC)
                .tag(METRIC_TAG, "shared poll")
                .tap(Micrometer.observation(observationRegistry))
                .doOnCancel(() -> log.info("Cancelled polling"))
                .doOnError(t -> log.error("Error polling the database", t))
                .doOnSubscribe(context::onStart)
                .retryWhen(Retry.backoff(Long.MAX_VALUE, interval).maxBackoff(interval.multipliedBy(4L)))
                .share();
```
