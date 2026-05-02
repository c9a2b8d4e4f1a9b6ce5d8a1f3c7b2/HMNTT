### Title
Unbounded Subscription Flooding Exhausts Shared `boundedElastic()` Scheduler in `PollingTopicListener`

### Summary
`PollingTopicListener.listen()` creates a per-subscription infinite polling loop (`RepeatSpec.times(Long.MAX_VALUE)`) that schedules delay tasks on the JVM-global `Schedulers.boundedElastic()` singleton. Because there is no limit on the total number of concurrent subscriptions and no authentication on the gRPC endpoint, an unprivileged attacker can open many connections (each carrying up to 5 streams) and saturate the shared scheduler's thread pool, queuing tasks indefinitely and introducing latency for every other reactive pipeline in the process that shares the same scheduler.

### Finding Description

**Exact code path:**

`grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java`, lines 31–48:

```java
private final Scheduler scheduler = Schedulers.boundedElastic();   // line 31

return Flux.defer(() -> poll(context))
        .delaySubscription(interval, scheduler)                     // line 39
        .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)                // line 40
                .jitter(0.1)
                .withFixedDelay(interval)
                .withScheduler(scheduler))                          // line 43
```

**Root cause — two compounding facts:**

1. `Schedulers.boundedElastic()` is a **JVM-global singleton** in Reactor. Every call to the static factory returns the same shared instance. The same scheduler is therefore used by:
   - `PollingTopicListener` (line 31) — delay + repeat for every live subscription
   - `SharedTopicListener.listen()` — `publishOn(Schedulers.boundedElastic(), …)` (line 25 of `SharedTopicListener.java`)
   - `TopicMessageServiceImpl.subscribeTopic()` — `safetyCheck.subscribeOn(Schedulers.boundedElastic())` (line 70)
   - `PollingTopicMessageRetriever` — its own `Schedulers.boundedElastic()` reference (line 41)

2. There is **no cap on total concurrent subscriptions**. `NettyProperties.maxConcurrentCallsPerConnection = 5` limits streams *per TCP connection*, but there is no `maxConnections` configured on the Netty server builder (`GrpcConfiguration.java` line 33), and the gRPC endpoint requires no authentication (`GrpcInterceptor.java` only sets an endpoint-context label). `subscriberCount` in `TopicMessageServiceImpl` is a Micrometer gauge — it is never checked against a threshold to reject new subscriptions.

**Exploit flow:**

An attacker opens *C* TCP connections and starts 5 `subscribeTopic` streams on each (no `limit` field, no `endTime`). Each stream calls `PollingTopicListener.listen()`, which schedules a `delaySubscription` task and then re-schedules a repeat task every `interval` (default 500 ms) on the shared `boundedElastic` pool. With the default thread cap of `10 × availableProcessors` (e.g. 100 threads on a 10-core node), once *C × 5 > 100* subscriptions are active the pool is saturated. Reactor then queues subsequent tasks (up to 100 000 per thread). Every other operation that needs a `boundedElastic` worker — including the safety-check gap-recovery query and the `publishOn` in `SharedTopicListener` — waits behind the attacker's queued delay tasks.

**Why existing checks fail:**

- `maxConcurrentCallsPerConnection = 5` is per-connection; opening 21+ connections trivially bypasses it.
- No IP-level rate limit or connection-count limit exists on the gRPC server.
- No authentication is required; the gRPC interceptor performs no access control.
- `subscriberCount` is observability-only and enforces nothing.

### Impact Explanation

All reactive pipelines sharing `Schedulers.boundedElastic()` experience queuing latency proportional to the number of attacker subscriptions. The safety-check mechanism (`Mono.delay(1s).subscribeOn(boundedElastic)`) that recovers missing messages for *legitimate* subscribers is delayed or starved. Under a sustained flood the mirror node's gRPC service degrades for all users without any crash or data corruption — a pure griefing / availability impact with no economic damage to the network itself.

### Likelihood Explanation

The gRPC port (default 5600) is publicly documented and reachable without credentials (the README shows unauthenticated `grpcurl` examples). Opening hundreds of TCP connections and issuing `subscribeTopic` RPCs with `limit=0` requires only a trivial script. The attack is repeatable and requires no special knowledge beyond the public protobuf definition. The only prerequisite is that the operator has configured `hiero.mirror.grpc.listener.type=POLL`; this is a supported, documented configuration option.

### Recommendation

1. **Enforce a global subscription cap**: Check `subscriberCount` in `TopicMessageServiceImpl.subscribeTopic()` before accepting a new subscription and return `RESOURCE_EXHAUSTED` when the limit is exceeded.
2. **Limit connections per IP**: Configure `NettyServerBuilder.maxConnectionsPerIp()` or add a gRPC `ServerInterceptor` that tracks and rejects connections beyond a per-source threshold.
3. **Use a dedicated scheduler**: Replace `Schedulers.boundedElastic()` in `PollingTopicListener` with a private, bounded `Schedulers.newBoundedElastic(…)` instance so attacker-induced saturation cannot spill over into other pipelines.
4. **Add per-IP rate limiting at the gRPC layer**: A `ServerInterceptor` using a token-bucket (similar to the existing `ThrottleConfiguration` in the web3 module) should gate new `subscribeTopic` calls.

### Proof of Concept

```bash
# Requires grpcurl and the mirror-node proto files.
# Open 25 connections × 5 streams = 125 concurrent polling subscriptions
# (exceeds default boundedElastic thread cap on a 10-core host)

for i in $(seq 1 25); do
  for j in $(seq 1 5); do
    grpcurl -plaintext \
      -d '{"topicID": {"topicNum": 1000}}' \
      localhost:5600 \
      com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
  done
done

# Observe: legitimate subscribeTopic calls now experience multi-second
# latency on the safety-check path and on SharedTopicListener.publishOn,
# visible via the hiero_mirror_grpc_consensus_latency_seconds metric
# (alert threshold: >15 s, see charts/hedera-mirror-common/alerts/rules.tf line 140).
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L67-70)
```java
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-25)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
```
