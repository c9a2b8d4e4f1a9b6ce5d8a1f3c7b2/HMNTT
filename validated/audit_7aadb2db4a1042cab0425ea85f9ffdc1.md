All code references were verified against the actual repository. Here is the result:

---

# Audit Report

## Title
Unbounded Subscription DoS via Far-Future `endTime` in `TopicMessageServiceImpl.subscribeTopic()`

## Summary
An unprivileged caller can open a `ConsensusTopicQuery` with `startTime=0` and `endTime` set to a far-future nanosecond value (e.g., `Long.MAX_VALUE`). The filter validation imposes no upper bound on `endTime`, and the `isComplete()` termination check will never return `true` for such a value, causing the subscription to hold resources indefinitely. Accumulating many such subscriptions exhausts server resources.

## Finding Description

**Validation gap — `TopicMessageFilter.java`, lines 43–51:**

`isValidEndTime()` only checks that `endTime > startTime` with no upper bound. `isValidStartTime()` accepts `startTime=0` because epoch 0 is before `now()`. Both constraints pass for `startTime=0, endTime=Long.MAX_VALUE`. [1](#0-0) 

**Non-terminating `isComplete()` — `TopicMessageServiceImpl.java`, lines 203–215:**

`Instant.ofEpochSecond(0, Long.MAX_VALUE)` resolves to approximately year 2262. Adding the 30-second `endTimeInterval` (confirmed in `GrpcProperties.java` line 22) changes nothing. `isBefore(Instant.now())` returns `false` for ~240 years, so `isComplete()` never returns `true`. [2](#0-1) [3](#0-2) 

**`pastEndTime()` never completes — lines 123–131:**

`Flux.empty().repeatWhen(...)` only completes when `isComplete()` returns `true`. Since that never happens, the `takeUntilOther(pastEndTime(topicContext))` at line 73 never fires, and the main subscription flux never terminates. [4](#0-3) [5](#0-4) 

**`takeWhile` never terminates — line 80:**

With `endTime=Long.MAX_VALUE`, no real message will ever have a `consensusTimestamp` that large, so this operator never terminates the stream. [6](#0-5) 

**Safety check runs indefinitely — lines 67–70:**

The `safetyCheck` flux polls for missing messages every second on a `boundedElastic` scheduler thread as long as `!topicContext.isComplete()`. Since `isComplete()` never returns `true`, this thread is held for the lifetime of the subscription. [7](#0-6) 

## Impact Explanation
Each immortal subscription holds: a `TopicContext` object, a `subscriberCount` slot (metric only, no cap enforced), a `boundedElastic` scheduler thread for the safety check, a live listener registration, and periodic `pastEndTime` polling every 30 seconds. Historical retrieval from `startTime=0` also triggers a full database scan of all topic messages from epoch. With no global subscription limit, an attacker opening multiple connections (each allowing up to `maxConcurrentCallsPerConnection` streams) can accumulate hundreds of such subscriptions, exhausting thread pools, memory, and database connection pools, rendering the mirror node service unavailable.

## Likelihood Explanation
The attack requires zero privileges. The gRPC `subscribeTopic` endpoint is publicly accessible. The crafted query is a single valid protobuf message. The per-connection call limit is trivially bypassed by opening additional connections. The attack is fully automatable.

## Recommendation
1. **Add an upper bound on `endTime`** in `TopicMessageFilter.isValidEndTime()`: reject any `endTime` beyond a reasonable horizon (e.g., `now() + some maximum duration`).
2. **Enforce a global subscription limit**: gate `subscribeTopic` on `subscriberCount` and reject new subscriptions when a configured maximum is reached.
3. **Cap historical retrieval depth**: reject or paginate queries where `startTime` is excessively far in the past to prevent full-table scans. [8](#0-7) 

## Proof of Concept
```python
import grpc
from proto import consensus_service_pb2_grpc, mirror_pb2

channel = grpc.insecure_channel("mirror-node:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

# endTime.seconds = 9223372035 maps to ~Long.MAX_VALUE nanoseconds in the filter
query = mirror_pb2.ConsensusTopicQuery(
    topicID=...,
    consensusStartTime=Timestamp(seconds=0, nanos=0),
    consensusEndTime=Timestamp(seconds=9223372035, nanos=0),
)

# Open many connections, each with multiple streams
for _ in range(200):
    stub.subscribeTopic(query)  # each call is immortal
```
Each call passes both `@AssertTrue` validators, enters the live listener phase, and never terminates. Accumulating 200+ such subscriptions exhausts the `boundedElastic` thread pool and database connection pool. [9](#0-8)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-51)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }

    @AssertTrue(message = "Start time must be before the current time")
    public boolean isValidStartTime() {
        return startTime <= DomainUtils.now();
    }
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L203-215)
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
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L22-22)
```java
    private Duration endTimeInterval = Duration.ofSeconds(30);
```
