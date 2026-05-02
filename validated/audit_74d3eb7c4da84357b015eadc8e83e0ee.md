Let me verify the exact code for the `TopicMessageService` interface and the `@Valid` annotation usage to complete the analysis.

All code paths are confirmed. Every step of the claim checks out against the actual source.

---

Audit Report

## Title
Integer Overflow in `poll()` Bypasses Page-Size Cap, Enabling Unbounded DB Query DoS

## Summary
When a gRPC client sends `limit = Long.MAX_VALUE` (a valid `uint64` value) to `subscribeTopic`, the value passes Spring's `@Min(0)` validation. Inside `PollingTopicMessageRetriever.poll()`, an unchecked narrowing cast `(int)(Long.MAX_VALUE - 0L)` overflows to `-1`. `Math.min(-1, maxPageSize)` yields `-1`, which is written into a new filter via a Lombok builder call that bypasses Spring AOP validation. The resulting filter has `limit = -1`, causing `hasLimit()` to return `false`, so `setMaxResults()` is never called and the JPA query fetches every matching row with no bound.

## Finding Description

**1. No upper-bound check at the entry point.**

`ConsensusController.toFilter()` passes the raw proto `uint64` directly to the filter builder with no cap: [1](#0-0) 

**2. `@Min(0)` does not reject `Long.MAX_VALUE`.**

The only constraint on `limit` is `@Min(0)`: [2](#0-1) 

Spring validation IS triggered — `TopicMessageService.subscribeTopic` carries `@Valid` on the parameter and `TopicMessageServiceImpl` is `@Validated`: [3](#0-2) 

`Long.MAX_VALUE >= 0`, so the constraint passes.

**3. Narrowing cast overflows in `poll()`.**

```
(int)(Long.MAX_VALUE - 0L)
= (int)(0x7FFFFFFFFFFFFFFF)
= (int)(0xFFFFFFFF)          // lower 32 bits
= -1
Math.min(-1, maxPageSize) = -1
``` [4](#0-3) 

**4. `toBuilder().limit(-1).build()` bypasses Spring AOP validation.**

The new filter is built via a Lombok builder on a plain value object — not a Spring-managed bean — so the `@Min(0)` constraint is never re-evaluated: [5](#0-4) 

**5. `hasLimit()` returns `false` for `-1`.** [6](#0-5) 

**6. `setMaxResults()` is never called — unbounded query.** [7](#0-6) 

`getResultList()` materialises the full result set into a Java `List` before any reactive back-pressure can act: [8](#0-7) 

The same overflow pattern exists identically in `PollingTopicListener.poll()`: [9](#0-8) 

## Impact Explanation
A single malicious `subscribeTopic` RPC with `limit = Long.MAX_VALUE` causes an unbounded `SELECT *` against the `topic_message` table. Because `getResultList()` materialises the entire result set before streaming, both the DB connection and JVM heap are exhausted. This can render the mirror node's gRPC service unavailable for all other subscribers — a non-network DoS requiring no authentication and no special knowledge of system internals.

## Likelihood Explanation
The `subscribeTopic` endpoint is publicly accessible with no authentication. The `limit` field in `ConsensusTopicQuery` is `uint64`; any gRPC client library can trivially set it to `Long.MAX_VALUE`. The attack is deterministic, requires a single RPC call, and is trivially repeatable.

## Recommendation

1. **Add an upper-bound cap in `ConsensusController.toFilter()`** before building the filter — reject or clamp any `limit` value that exceeds `Integer.MAX_VALUE` (or a configured maximum).
2. **Replace the unchecked narrowing cast** in both `PollingTopicMessageRetriever.poll()` and `PollingTopicListener.poll()` with a safe computation, e.g.:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (int) Math.min(remaining, Integer.MAX_VALUE);
   ```
3. **Add a hard maximum to `TopicMessageFilter`** via a custom `@Max` or cross-field constraint so that no filter with `limit > MAX_SAFE_VALUE` can be constructed anywhere in the codebase.

## Proof of Concept

```java
// Any gRPC client
ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
    .setTopicID(TopicID.newBuilder().setTopicNum(1).build())
    .setConsensusStartTime(Timestamp.newBuilder().setSeconds(0).build())
    .setLimit(Long.MAX_VALUE)   // 9223372036854775807 — valid uint64, passes @Min(0)
    .build();

// Single call triggers:
// (int)(Long.MAX_VALUE - 0) = -1
// Math.min(-1, maxPageSize)  = -1
// hasLimit() on newFilter    = false  (-1 > 0 is false)
// setMaxResults() skipped    → SELECT * FROM topic_message WHERE topic_id=1 AND consensus_timestamp>=0
// getResultList() materialises every row into heap before reactive stream can limit output
blockingStub.subscribeTopic(query);
```

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-59)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```
