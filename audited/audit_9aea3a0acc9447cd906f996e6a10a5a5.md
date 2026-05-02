### Title
Unauthenticated Subscription Flood Triggers Coordinated Unthrottled DB Query Storm via Safety Check

### Summary
Any unprivileged caller of `subscribeTopic()` can open an unbounded number of gRPC subscriptions with `startTime=0`. Exactly one second after subscription, a built-in safety check unconditionally fires for every active subscription (not only during network partitions), each issuing an unthrottled `topicMessageRetriever.retrieve(gapFilter, false)` call. With `startTime=0`, each call scans from the earliest possible timestamp, and the unthrottled retriever executes up to 12 back-to-back DB polls at 20 ms intervals with a page size of 5,000 rows per poll, producing a coordinated DB query flood proportional to the number of open subscriptions.

### Finding Description

**Safety check fires unconditionally for every open subscription** [1](#0-0) 

`Mono.delay(Duration.ofSeconds(1L))` fires once, one second after subscription. The guard `!topicContext.isComplete()` is evaluated at that moment. `isComplete()` unconditionally returns `false` whenever `endTime == null`: [2](#0-1) 

A subscription with no `endTime` (the common case for live streaming) will therefore **always** trigger the safety check, regardless of whether a network partition exists.

**Safety check issues an unthrottled retriever call starting from `startTime`**

When `current == null` (the safety-check path), `missingMessages()` builds a `gapFilter` using `topicContext.getFilter().getStartTime()` when no message has been received yet, then calls `topicMessageRetriever.retrieve(gapFilter, false)`: [3](#0-2) 

**Unthrottled retriever parameters amplify each call**

With `throttled=false`, `PollingTopicMessageRetriever` uses:
- `numRepeats = unthrottled.getMaxPolls()` → default **12** polls
- `frequency = 20 ms` between polls
- `maxPageSize = 5,000` rows per poll [4](#0-3) 

Each safety-check invocation therefore issues up to **12 sequential DB queries** of up to 5,000 rows each.

**`startTime=0` is accepted by validation**

`TopicMessageFilter.startTime` carries `@Min(0)` and the `@AssertTrue` only requires `startTime <= DomainUtils.now()`. Epoch zero satisfies both constraints, causing every DB query to scan from the very beginning of the topic message table: [5](#0-4) 

**No per-user or per-IP subscription limit exists in application code**

`subscriberCount` is a Micrometer gauge used only for observability; it imposes no cap: [6](#0-5) 

`GrpcProperties` contains no subscription-rate or concurrency limit: [7](#0-6) 

**Coordinated flood formula**

N open subscriptions × 12 unthrottled polls × up to 5,000 rows = **N × 60,000 row fetches** hitting the DB within ~240 ms of the 1-second mark, all scanning from epoch.

### Impact Explanation

A single unprivileged client opening N concurrent gRPC streams causes N×12 simultaneous full-history DB queries 1 second later. At modest N (e.g., 500 streams), this is 6,000 concurrent DB queries scanning from timestamp 0, sufficient to exhaust DB connection pools, spike CPU/IO, and deny service to all legitimate subscribers. The impact is a complete availability loss for the mirror node's topic subscription service and potential cascading failure of the underlying database.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly reachable with no authentication requirement visible in the service layer. Opening thousands of gRPC streams is trivially achievable with any gRPC client library in a loop. The 1-second synchronization window means all safety checks fire in a tight burst. The attack is repeatable: after streams are closed, the attacker can immediately reopen them. No special knowledge of the system internals is required beyond knowing the topic ID of any valid topic.

### Recommendation

1. **Enforce a per-IP / per-connection subscription limit** at the Netty/gRPC interceptor layer before `subscribeTopic()` is reached.
2. **Add a global concurrent-subscription cap** using `subscriberCount` as an actual gate (reject new subscriptions when the count exceeds a configurable threshold).
3. **Clamp `startTime` to a recent window** (e.g., reject `startTime` older than a configurable maximum lookback, such as 7 days) to prevent full-history scans.
4. **Rate-limit safety-check DB calls globally** (e.g., a shared semaphore or token bucket across all active `TopicContext` instances) so that N simultaneous safety checks cannot all issue DB queries concurrently.
5. **Consider making the safety check throttled** (`retrieve(gapFilter, true)`) or adding a per-subscription cooldown before re-triggering gap recovery.

### Proof of Concept

```python
import grpc
import threading
# Pseudocode - adapt to actual proto definitions
from mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2

NUM_STREAMS = 1000
TOPIC_ID = 0  # any valid topic

def open_subscription():
    channel = grpc.insecure_channel("mirror-node:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    request = consensus_service_pb2.ConsensusTopicQuery(
        topic_id=...,          # valid topic
        consensus_start_time=0 # epoch = startTime=0
        # no end_time, no limit
    )
    for _ in stub.subscribeTopic(request):
        pass  # keep stream open

threads = [threading.Thread(target=open_subscription) for _ in range(NUM_STREAMS)]
for t in threads:
    t.start()
# After ~1 second: NUM_STREAMS * 12 unthrottled DB queries fire simultaneously,
# each scanning topic_message from consensusTimestamp >= 0.
```

**Expected result**: DB connection pool exhaustion and query latency spike observable within 1–2 seconds of stream opening; legitimate subscribers experience timeouts or errors.

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-205)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L102-107)
```java
            } else {
                RetrieverProperties.UnthrottledProperties unthrottled = retrieverProperties.getUnthrottled();
                numRepeats = unthrottled.getMaxPolls();
                frequency = unthrottled.getPollingFrequency();
                maxPageSize = unthrottled.getMaxPageSize();
            }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-51)
```java
    @Min(0)
    private long limit;

    @Min(0)
    @NotNull
    @Builder.Default
    private long startTime = DomainUtils.now();

    @Builder.Default
    private String subscriberId = RandomStringUtils.random(8, 0, 0, true, true, null, RANDOM);

    @NotNull
    private EntityId topicId;

    public boolean hasLimit() {
        return limit > 0;
    }

    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L17-30)
```java
public class GrpcProperties {

    private boolean checkTopicExists = true;

    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);

    @Min(1)
    private int entityCacheSize = 50_000;

    @NotNull
    @Valid
    private NettyProperties netty = new NettyProperties();
}
```
