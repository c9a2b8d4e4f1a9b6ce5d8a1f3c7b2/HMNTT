### Title
Unbounded `endTime=Long.MAX_VALUE` Bypasses Subscription Termination, Enabling Indefinite Resource Exhaustion via gRPC Topic Subscription

### Summary
Any unprivileged caller of `subscribeTopic()` can supply `endTime = Long.MAX_VALUE`. The only validation check (`endTime > startTime`) passes trivially, and `isComplete()` converts `Long.MAX_VALUE` nanoseconds to approximately year 2262 via `Instant.ofEpochSecond(0, Long.MAX_VALUE)`, which is always in the future. The subscription never terminates, and the `pastEndTime` polling loop fires every 30 seconds indefinitely per subscription, consuming scheduler threads, gRPC connections, and database resources.

### Finding Description

**Validation gap — `TopicMessageFilter.isValidEndTime()`:** [1](#0-0) 

The only constraint is `endTime > startTime`. `Long.MAX_VALUE` (9,223,372,036,854,775,807 ns) is always greater than any current-time nanosecond value, so the check passes unconditionally.

**`isComplete()` never returns `true`:** [2](#0-1) 

`Instant.ofEpochSecond(0, Long.MAX_VALUE)` normalises to `Instant.ofEpochSecond(9223372036, 854775807)` — approximately year 2262. Adding `endTimeInterval` (30 s) and calling `.isBefore(Instant.now())` always returns `false`. The method therefore always returns `false` for this input.

**`pastEndTime()` polling loop runs forever:** [3](#0-2) 

Because `endTime != null`, the method does not return `Flux.never()`. Instead it creates a `RepeatSpec` conditioned on `!topicContext.isComplete()`, which is always `true`. The loop fires every 30 seconds indefinitely, re-subscribing to `Flux.empty()` on the bounded-elastic scheduler, but never emitting a value. `takeUntilOther(pastEndTime(...))` therefore never fires.

**`takeWhile` also never terminates:** [4](#0-3) 

`t.getConsensusTimestamp() < Long.MAX_VALUE` is always `true` for any real consensus timestamp (current epoch nanoseconds ≈ 1.7 × 10¹⁸, far below `Long.MAX_VALUE` ≈ 9.2 × 10¹⁸).

**No per-user or global subscription cap:** [5](#0-4) 

`subscriberCount` is a metrics gauge only — it is never checked against a maximum. The only server-side limit is `maxConcurrentCallsPerConnection = 5` per TCP connection. [6](#0-5) 

An attacker opens N connections × 5 calls each = 5N indefinite subscriptions.

### Impact Explanation

Each pinned subscription holds: one gRPC server stream, one Reactor subscription chain, one bounded-elastic scheduler task firing every 30 seconds, and (via the safety-check path) periodic database polling. With no authentication and no per-IP or per-user subscription limit, an attacker can exhaust the bounded-elastic thread pool, saturate database connection pools, and degrade or deny service to all legitimate subscribers. Severity: **High** (availability impact, no authentication required, fully repeatable).

### Likelihood Explanation

The gRPC endpoint is publicly reachable. No credentials are required to call `subscribeTopic()`. The only precondition is that a valid topic ID exists, which is publicly known for any active HCS topic. The exploit requires a single crafted protobuf field (`consensusEndTime` set to `Long.MAX_VALUE`). It is trivially scriptable and repeatable from a single host by opening multiple TCP connections.

### Recommendation

1. **Add an upper-bound validator on `endTime`** in `TopicMessageFilter`:
   ```java
   @AssertTrue(message = "End time must not exceed a reasonable future bound")
   public boolean isValidEndTimeBound() {
       return endTime == null || endTime <= DomainUtils.now() + MAX_SUBSCRIPTION_WINDOW_NS;
   }
   ```
   where `MAX_SUBSCRIPTION_WINDOW_NS` is a configurable cap (e.g., 30 days in nanoseconds).

2. **Enforce a maximum concurrent subscription count** (globally and/or per source IP) in `subscribeTopic()`, rejecting new subscriptions when the limit is reached.

3. **Add a maximum subscription lifetime** independent of `endTime`, forcibly terminating streams that have been open longer than a configured threshold.

### Proof of Concept

```
# Using grpcurl against a running mirror-node gRPC endpoint:
grpcurl -plaintext -d '{
  "topicID": {"shardNum": 0, "realmNum": 0, "topicNum": 1},
  "consensusStartTime": {"seconds": 0, "nanos": 0},
  "consensusEndTime":   {"seconds": 9223372036, "nanos": 854775807}
}' <host>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

1. Open 5 such streams per TCP connection.
2. Open N TCP connections from the same or multiple hosts.
3. Each stream holds a `pastEndTime` polling task firing every 30 s and a live `topicListener` subscription.
4. Observe `hiero.mirror.grpc.subscribers` gauge climbing without bound and bounded-elastic thread pool saturation.
5. Legitimate subscribers begin receiving errors or timeouts as server resources are exhausted.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L43-46)
```java
    @AssertTrue(message = "End time must be after start time")
    public boolean isValidEndTime() {
        return endTime == null || endTime > startTime;
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L48-48)
```java
    private final AtomicLong subscriberCount = new AtomicLong(0L);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L79-81)
```java
        if (filter.getEndTime() != null) {
            flux = flux.takeWhile(t -> t.getConsensusTimestamp() < filter.getEndTime());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L14-14)
```java
    private int maxConcurrentCallsPerConnection = 5;
```
