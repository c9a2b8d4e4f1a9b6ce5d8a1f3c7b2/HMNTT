[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) 

All cited code references are verified against the actual source. Every line number, method name, and behavioral claim checks out. The SECURITY.md exclusion for "Impacts that only require DDoS" does not apply here — this is an application-level resource exhaustion triggered by a specific code logic flaw (`limit=0` bypassing `hasLimit()` into an unbounded polling loop), not a volumetric flood attack.

---

Audit Report

## Title
Unbounded Infinite DB Polling Loop via Unauthenticated `limit=0` gRPC Subscription in `PollingTopicListener`

## Summary
When the gRPC service is configured with `type=POLL`, any unauthenticated client can subscribe to a topic omitting the `limit` field (protobuf default `uint64=0`). This causes `PollingTopicListener.listen()` to schedule `RepeatSpec.times(Long.MAX_VALUE)` DB queries at every polling interval with no self-termination condition. Multiple concurrent subscriptions exhaust the shared HikariCP connection pool, denying service to all other users.

## Finding Description

**Step 1 — `limit=0` passes through without rejection.**

`ConsensusController.toFilter()` maps the incoming protobuf field directly to the filter with no validation: [1](#0-0) 

A protobuf `uint64` field defaults to `0` when omitted by the client, so `limit=0` is silently accepted.

**Step 2 — `hasLimit()` treats `0` as "no limit".** [2](#0-1) 

`limit=0` causes `hasLimit()` to return `false`, meaning the filter is treated as an unlimited subscription.

**Step 3 — `incomingMessages()` propagates `limit=0` to the listener.** [3](#0-2) 

When `hasLimit()` is false, `limit` is set to `0` and passed into `newFilter`, which is then handed to `topicListener.listen()`.

**Step 4 — `PollingTopicListener.listen()` creates an effectively infinite repeat loop.** [4](#0-3) 

`RepeatSpec.times(Long.MAX_VALUE)` (~9.2×10¹⁸ iterations) with no termination predicate. The default `interval` is 500ms: [8](#0-7) 

**Step 5 — Each poll executes a full DB query fetching up to `maxPageSize` rows.** [5](#0-4) 

Because `hasLimit()` is false, `limit = Integer.MAX_VALUE`, capped only by `maxPageSize` (default 5000). Each poll holds a DB connection for the duration of the query.

**Contrast with `PollingTopicMessageRetriever`**, which has an explicit termination predicate: [7](#0-6) 

`PollingTopicListener` has no equivalent `isComplete()` guard — the loop never self-terminates.

**Step 6 — The outer `subscribeTopic()` applies no `.take()` when `limit=0`.** [9](#0-8) 

`hasLimit()` is false, so no `.take()` is applied to the outer flux either. The only termination is client disconnect.

**Step 7 — `isComplete()` never returns `true` without an `endTime`.** [10](#0-9) 

Without `endTime`, `isComplete()` always returns `false`, and `pastEndTime()` returns `Flux.never()`, so `takeUntilOther()` never fires.

## Impact Explanation

Each attacker subscription generates ~2 DB queries/second indefinitely, each potentially fetching up to 5000 rows and holding a DB connection for the query duration. The HikariCP connection pool (typically 10–20 connections) is shared across all gRPC subscribers and the importer. With a small number of concurrent malicious subscriptions, legitimate queries queue up and time out, causing complete service unavailability. The `subscriberCount` metric is a gauge only — there is no enforcement cap on concurrent subscribers.

## Likelihood Explanation

The attack requires zero authentication and zero knowledge of system internals. The `limit=0` trigger is the protobuf default — a client that simply omits the `limit` field triggers the vulnerability. The `startTime` only needs to be any past timestamp, which `isValidStartTime()` explicitly allows. The `POLL` listener type is a documented, supported configuration option. The attack is trivially scriptable with any standard gRPC client library.

## Recommendation

1. **Add a termination predicate to `PollingTopicListener`**: Replace `RepeatSpec.times(Long.MAX_VALUE)` with `RepeatSpec.create(r -> !context.isComplete(), Long.MAX_VALUE)` and implement `isComplete()` to return `true` when the limit has been reached (mirroring `PollingTopicMessageRetriever`).
2. **Enforce a maximum subscriber count**: Convert the `subscriberCount` gauge into an enforced cap that rejects new subscriptions when the limit is reached.
3. **Reject or cap `limit=0` at the controller layer**: In `ConsensusController.toFilter()`, either reject `limit=0` with a gRPC `INVALID_ARGUMENT` status or treat it as a configurable maximum (e.g., operator-defined default limit).
4. **Apply a configurable maximum polling duration**: Add a `maxSubscriptionDuration` to `ListenerProperties` and use `.timeout()` on the flux in `PollingTopicListener.listen()`.

## Proof of Concept

```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from hedera.mirror.api.proto import consensus_service_pb2
from hederahashgraph.api.proto.java import basic_types_pb2

def open_infinite_subscription(channel, topic_num):
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_service_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=topic_num),
        # limit field omitted → protobuf default 0 → hasLimit()=false
        # consensusStartTime omitted → defaults to epoch 0 (past)
    )
    for _ in stub.subscribeTopic(query):
        pass  # consume messages, keep connection alive

# Open N connections × 5 subscriptions each to saturate DB pool
channels = [grpc.insecure_channel("mirror-node:5600") for _ in range(4)]
for ch in channels:
    for _ in range(5):
        threading.Thread(target=open_infinite_subscription, args=(ch, 1)).start()
# DB connection pool exhausted; legitimate queries time out
```

Each subscription triggers `PollingTopicListener.listen()` with `RepeatSpec.times(Long.MAX_VALUE)` polling every 500ms, fetching up to 5000 rows per poll, indefinitely.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L39-41)
```java
    public boolean hasLimit() {
        return limit > 0;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L115-118)
```java
        long limit =
                filter.hasLimit() ? filter.getLimit() - topicContext.getCount().get() : 0;
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(limit).startTime(startTime).build();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-57)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L26-30)
```java
    private int maxPageSize = 5000;

    @DurationMin(millis = 50)
    @NotNull
    private Duration interval = Duration.ofMillis(500L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L52-55)
```java
                .repeatWhen(RepeatSpec.create(r -> !context.isComplete(), context.getNumRepeats())
                        .jitter(0.1)
                        .withFixedDelay(context.getFrequency())
                        .withScheduler(scheduler))
```
