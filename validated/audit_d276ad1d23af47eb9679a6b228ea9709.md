I have verified all code references. Let me confirm the final detail about the `@Min(0)` validation enforcement path.

All code references are confirmed. The vulnerability is real and fully traceable through the codebase.

---

## Audit Report

## Title
Integer Overflow in `poll()` Removes SQL LIMIT, Enabling Unlimited Full-Index Scan via Crafted `limit` Value

## Summary
In `PollingTopicMessageRetriever.poll()` (and identically in `PollingTopicListener.poll()`), the expression `(int)(filter.getLimit() - context.getTotal().get())` performs an unsafe narrowing cast from `long` to `int`. Any `limit` value greater than `Integer.MAX_VALUE` (e.g., `2147483648L`) overflows to a negative `int`. `Math.min` selects that negative value as `pageSize`, which is stored as a negative `long` in the rebuilt `newFilter`. Since `hasLimit()` returns `false` for non-positive values, `setMaxResults()` is never called, and the JPA query fetches every row for the topic without any row cap.

## Finding Description

**Step 1 — Attacker-controlled input reaches `limit` without an upper bound.**

`ConsensusController.toFilter()` reads `query.getLimit()` directly from the protobuf `uint64` field and passes it to `TopicMessageFilter.builder().limit(...)`: [1](#0-0) 

The only constraint on `TopicMessageFilter.limit` is `@Min(0)`, which rejects negative values but accepts any positive `long`, including values above `Integer.MAX_VALUE`: [2](#0-1) 

**Step 2 — Spring `@Valid` validates the original filter but cannot catch the overflow.**

`TopicMessageService.subscribeTopic` carries `@Valid` on its parameter, so Spring AOP validates the caller-supplied filter: [3](#0-2) 

A `limit` of `2147483648L` satisfies `@Min(0)` and passes validation. The poisoned `newFilter` is constructed entirely inside `poll()` and never passes through a Spring-managed validation boundary.

**Step 3 — Narrowing cast overflows inside `poll()`.**

With `filter.getLimit() = 2147483648L` and `context.getTotal().get() = 0`:
- `(int)(2147483648L - 0L)` → `(int)2147483648L` → `-2147483648` (`Integer.MIN_VALUE`)
- `Math.min(-2147483648, maxPageSize)` → `-2147483648`
- `newFilter` is built with `limit = -2147483648L` [4](#0-3) 

The identical overflow exists in `PollingTopicListener.poll()`: [5](#0-4) 

**Step 4 — `hasLimit()` returns `false` for the negative value.**

`hasLimit()` uses `limit > 0`, so `-2147483648` evaluates to `false`: [6](#0-5) 

**Step 5 — `setMaxResults()` is never called; all rows are loaded.**

`TopicMessageRepositoryCustomImpl.findByFilter()` gates `setMaxResults()` on `hasLimit()`. With `hasLimit()` returning `false`, no SQL `LIMIT` is applied, and `getResultList()` loads the entire result set into a Java `List`: [7](#0-6) [8](#0-7) 

**Step 6 — `isComplete()` never terminates the polling loop.**

`isComplete()` compares `filter.getLimit() == total.get()`, where `filter.getLimit()` is `2147483648L`. `total` would need to reach that value to self-terminate, which is unreachable in practice: [9](#0-8) 

**Step 7 — `flux.take(filter.getLimit())` provides no practical cap.**

`TopicMessageServiceImpl.subscribeTopic()` calls `flux.take(2147483648L)`, which is effectively unlimited: [10](#0-9) 

## Impact Explanation
On every poll cycle the repository executes a query with no `LIMIT` clause against the `topic_message` table, filtered only by `topic_id` and `consensus_timestamp >= startTime`. For a high-volume topic this returns millions of rows, all loaded into a Java `List` in a single call via `getResultList()`. This causes:
- **Memory exhaustion / OOM** on the mirror-node JVM.
- **Heavy database I/O** proportional to the number of stored messages for the targeted topic.
- **Denial of service** for all other subscribers sharing the same node, repeatable on every poll interval for as long as the subscription is open.

## Likelihood Explanation
The gRPC endpoint is publicly reachable with no authentication. The protobuf `uint64 limit` field accepts any 64-bit value. An attacker needs only to send a single `subscribeTopic` RPC with `limit = 2147483648` (one above `Integer.MAX_VALUE`). The attack is trivially scriptable, repeatable, and requires no prior knowledge of the system beyond the public proto definition.

## Recommendation
Replace the unsafe narrowing cast with a bounds-safe computation. In `PollingTopicMessageRetriever.poll()` and `PollingTopicListener.poll()`, change:

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())
        : Integer.MAX_VALUE;
```

to:

```java
int limit = filter.hasLimit()
        ? (int) Math.min(filter.getLimit() - context.getTotal().get(), Integer.MAX_VALUE)
        : Integer.MAX_VALUE;
```

Additionally, add an `@Max(Integer.MAX_VALUE)` constraint to `TopicMessageFilter.limit` to reject oversized values at the API boundary before they reach internal logic.

## Proof of Concept

```python
import grpc
from com.hedera.mirror.api.proto import consensus_pb2, consensus_pb2_grpc
from com.hederahashgraph.api.proto.java import basic_types_pb2, timestamp_pb2

channel = grpc.insecure_channel("mirror-node-host:5600")
stub = consensus_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_pb2.ConsensusTopicQuery(
    topicID=basic_types_pb2.TopicID(topicNum=<valid_topic_id>),
    consensusStartTime=timestamp_pb2.Timestamp(seconds=0, nanos=0),
    # Integer.MAX_VALUE + 1 = 2147483648 triggers the overflow
    limit=2147483648
)

# Each message received triggers a poll with no SQL LIMIT
for response in stub.subscribeTopic(query):
    pass  # server OOMs or becomes unresponsive
```

On each poll interval, `PollingTopicMessageRetriever.poll()` computes `(int)(2147483648L - 0L)` = `-2147483648`, passes it as `newFilter.limit`, `hasLimit()` returns `false`, and `TopicMessageRepositoryCustomImpl.findByFilter()` executes `SELECT ... FROM topic_message WHERE topic_id = ? AND consensus_timestamp >= ?` with no `LIMIT` clause, loading the full table partition into JVM heap.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageService.java (L12-12)
```java
    Flux<TopicMessage> subscribeTopic(@Valid TopicMessageFilter filter);
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-75)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
        var startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        context.getPageSize().set(0L);

        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L121-128)
```java
        boolean isComplete() {
            boolean limitHit = filter.hasLimit() && filter.getLimit() == total.get();

            if (throttled) {
                return pageSize.get() < retrieverProperties.getMaxPageSize() || limitHit;
            }

            return limitHit;
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L60-60)
```java
        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```
