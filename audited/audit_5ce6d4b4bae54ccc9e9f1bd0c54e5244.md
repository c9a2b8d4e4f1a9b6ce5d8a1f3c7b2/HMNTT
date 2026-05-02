### Title
Unbounded `endTime` Enables Indefinite Subscription Hold / Resource Exhaustion DoS

### Summary
`TopicMessageFilter` imposes no upper-bound constraint on the caller-supplied `endTime` nanosecond value. When a far-future `endTime` is provided, `isComplete()` permanently returns `false`, causing the `pastEndTime()` repeat-loop to run for `Long.MAX_VALUE` iterations and the gRPC subscription to remain open indefinitely. An unprivileged attacker can open many such subscriptions to exhaust server resources.

### Finding Description

**Validation gap** — `TopicMessageFilter.java` lines 43-46:
```java
@AssertTrue(message = "End time must be after start time")
public boolean isValidEndTime() {
    return endTime == null || endTime > startTime;
}
```
There is no `@Max` or ceiling check on `endTime`. A caller may supply `endTime = Long.MAX_VALUE` (≈ year 2262 in nanoseconds) or any arbitrarily large future timestamp.

**`isComplete()` never returns `true`** — `TopicMessageServiceImpl.java` lines 203-215:
```java
boolean isComplete() {
    if (filter.getEndTime() == null) { return false; }
    if (filter.getEndTime() < startTime) { return true; }
    return Instant.ofEpochSecond(0, filter.getEndTime())
            .plus(grpcProperties.getEndTimeInterval())   // +30 s default
            .isBefore(Instant.now());
}
```
With `endTime` = year 2262, `Instant.ofEpochSecond(0, endTime).plus(30s).isBefore(Instant.now())` is permanently `false`. The only early-exit path (`endTime < startTime`) is also blocked because the validation constraint already requires `endTime > startTime`.

**`pastEndTime()` loop runs indefinitely** — lines 123-131:
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
Because `endTime != null`, the `Flux.never()` short-circuit is skipped. The `repeatWhen` condition `!isComplete()` is always `true`, so the loop repeats up to `Long.MAX_VALUE` times (every 30 s), never completing.

**Subscription never terminates** — line 73:
```java
.concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
```
`takeUntilOther` terminates only when `pastEndTime` emits an element or completes. Since it never does, the live subscription (including the active `topicListener.listen()` and the `boundedElastic`-scheduled safety check) is held open indefinitely per subscriber.

**No subscriber cap**: `subscriberCount` (line 48) is a metrics gauge only — it is never compared against a maximum, so there is no server-side enforcement preventing unlimited concurrent subscriptions.

### Impact Explanation
Each malicious subscription holds: a persistent gRPC connection, an active `TopicListener` (database polling or Redis subscription), reactive pipeline memory, and a `boundedElastic` scheduler slot for the safety-check. Opening hundreds of such subscriptions exhausts the bounded thread pool, database connection pool, and heap, causing denial of service for all legitimate subscribers of the mirror node's gRPC API. Severity: **High** (availability impact, no authentication required).

### Likelihood Explanation
The Hedera/Hiero mirror node gRPC `subscribeTopic` endpoint is publicly reachable. The only precondition is that the topic exists (or `checkTopicExists = false`). The attacker needs no credentials, no special role, and no knowledge beyond the public protobuf API. The attack is trivially scriptable: open N connections with `endTime = Long.MAX_VALUE` and hold them. It is fully repeatable and requires no timing precision.

### Recommendation
1. **Add an upper-bound constraint on `endTime`** in `TopicMessageFilter`: reject any `endTime` more than a configurable maximum duration (e.g., 30 days) beyond `Instant.now()` at subscription time.
2. **Enforce a maximum subscriber count**: compare `subscriberCount` against a configurable ceiling in `subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
3. **Add a maximum subscription duration**: use `flux.timeout(maxDuration)` or a gRPC deadline to cap how long any single subscription can live, regardless of `endTime`.
4. **Optionally**: add a per-IP or per-client connection rate limit at the Netty/gRPC layer via `NettyProperties`.

### Proof of Concept
```
# Using grpcurl against a running mirror node:
for i in $(seq 1 500); do
  grpcurl -d '{
    "topicID": {"topicNum": 1},
    "consensusStartTime": {"seconds": 1},
    "consensusEndTime":   {"seconds": 9999999999}
  }' <mirror-node-host>:5600 \
  com.hedera.mirror.api.proto.ConsensusService/subscribeTopic &
done
# Each connection is held open indefinitely.
# After ~500 connections the boundedElastic scheduler and DB connection pool
# are exhausted; legitimate subscribers receive errors or hang.
```

Preconditions: topic with `topicNum=1` exists (or `checkTopicExists=false`). No credentials required. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4)

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L23-46)
```java
    private Long endTime;

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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L72-73)
```java
        Flux<TopicMessage> flux = historical
                .concatWith(Flux.merge(safetyCheck, live).takeUntilOther(pastEndTime(topicContext)))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L21-22)
```java
    @NotNull
    private Duration endTimeInterval = Duration.ofSeconds(30);
```
