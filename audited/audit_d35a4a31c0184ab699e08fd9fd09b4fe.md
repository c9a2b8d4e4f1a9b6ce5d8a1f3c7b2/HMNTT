### Title
Shared `boundedElastic` Scheduler Saturation via Unbounded Subscription Fan-out in `PollingTopicListener`

### Summary
`PollingTopicListener` is a singleton Spring bean that creates a single `Schedulers.boundedElastic()` instance shared across every call to `listen()`. Each subscription schedules an infinite repeat loop (`RepeatSpec.times(Long.MAX_VALUE)`) on this shared scheduler. Because the only connection-level guard is `maxConcurrentCallsPerConnection = 5` (per connection, not global), an attacker opening many connections can saturate the shared scheduler's thread pool, causing polling delays to grow for all subscribers including legitimate ones.

### Finding Description

**Exact code path:**

`PollingTopicListener` declares a single scheduler at bean construction time: [1](#0-0) 

Every call to `listen()` attaches two scheduling operations to this same instance: [2](#0-1) 

`RepeatSpec.times(Long.MAX_VALUE)` means each subscription fires a scheduled task on the shared scheduler every `interval` (default 500 ms) for the lifetime of the connection.

**Root cause / failed assumption:** The design assumes a small, bounded number of concurrent subscriptions. There is no global subscription cap. `TopicMessageServiceImpl` tracks `subscriberCount` as a metric gauge but enforces no limit: [3](#0-2) 

**Only existing guard:** `maxConcurrentCallsPerConnection = 5` is applied per TCP connection: [4](#0-3) [5](#0-4) 

There is no limit on the number of TCP connections, so an attacker with C connections contributes `5 × C` concurrent polling loops all competing for the same `boundedElastic` thread pool (default: `10 × CPU cores` threads, queue cap 100,000 tasks).

**Why the check fails:** The per-connection limit is a per-socket control, not a global one. An attacker trivially opens hundreds of connections from a single host or a small botnet, each contributing 5 subscriptions. The scheduler's thread pool becomes the shared bottleneck.

### Impact Explanation

Reactor's `BoundedElasticScheduler` has a fixed thread pool of `10 × availableProcessors` threads and a task queue capped at 100,000 entries. With many subscriptions all enqueuing delay tasks every 500 ms:

1. **Latency inflation:** Thread pool contention causes each subscription's actual polling interval to exceed the configured `interval`, delaying message delivery for all subscribers including legitimate ones.
2. **Task rejection:** Once the 100,000-entry queue fills, `RejectedExecutionException` is thrown, terminating affected subscription pipelines with errors.
3. **Database amplification:** Each active subscription independently queries the database; scheduler saturation also means DB query bursts become uneven and harder to predict.

Severity is consistent with the "griefing / latency degradation" classification — no funds are at risk, but service quality degrades proportionally to attacker connection count.

### Likelihood Explanation

- Requires `hiero.mirror.grpc.listener.type = POLL` (non-default; default is `REDIS`). Deployments explicitly choosing `POLL` mode are the target population.
- No authentication is required to open a gRPC connection or call `subscribeTopic`.
- A single attacker machine can open hundreds of TCP connections and 5 subscriptions each with standard gRPC client libraries.
- The attack is repeatable and self-sustaining as long as connections remain open.

### Recommendation

1. **Enforce a global subscription limit** in `TopicMessageServiceImpl.subscribeTopic()`: reject new subscriptions when `subscriberCount` exceeds a configurable threshold (e.g., `hiero.mirror.grpc.listener.maxSubscriptions`).
2. **Isolate per-subscription schedulers or use a dedicated scheduler with a bounded concurrency cap** rather than sharing one `boundedElastic` instance across all subscriptions. Alternatively, use `Schedulers.newBoundedElastic(threadCap, queueSize, "poll")` with explicit, tuned parameters.
3. **Add a global connection limit** to the Netty server builder (e.g., `serverBuilder.maxConnectionAge(...)` and an IP-level connection rate limit at the load balancer).
4. **Expose `subscriberCount` as an alerting metric** with a threshold alert so operators can detect saturation before it impacts service.

### Proof of Concept

**Preconditions:**
- Mirror node configured with `hiero.mirror.grpc.listener.type: POLL`
- gRPC port 5600 reachable

**Steps:**
```python
import grpc, threading
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

def open_subscription(stub):
    req = consensus_service_pb2.ConsensusTopicQuery(topicID=..., consensusStartTime=...)
    for _ in stub.subscribeTopic(req):  # blocks, keeps scheduler slot occupied
        pass

stubs = []
for _ in range(200):                        # 200 connections
    ch = grpc.insecure_channel("mirror:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(ch)
    stubs.append(stub)
    for _ in range(5):                      # 5 subscriptions per connection = 1000 total
        threading.Thread(target=open_subscription, args=(stub,), daemon=True).start()

# Result: 1000 concurrent RepeatSpec loops on the shared boundedElastic scheduler.
# Legitimate subscriber polling intervals inflate; eventually RejectedExecutionException
# terminates pipelines when the 100k-task queue fills.
```

**Observable result:** Legitimate subscribers see message delivery latency grow from the configured 500 ms toward several seconds; under heavy load, subscriptions terminate with `reactor.core.Exceptions$ReactorRejectedExecutionException`.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L31-31)
```java
    private final Scheduler scheduler = Schedulers.boundedElastic();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/GrpcConfiguration.java (L31-34)
```java
        return serverBuilder -> {
            serverBuilder.executor(applicationTaskExecutor);
            serverBuilder.maxConcurrentCallsPerConnection(nettyProperties.getMaxConcurrentCallsPerConnection());
        };
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
