After reading the actual source files, I can verify the technical claims against the real code.

**Verified facts:**

1. `PollingTopicMessageRetriever.java` line 69: `(int) (filter.getLimit() - context.getTotal().get())` — unchecked `long→int` narrowing cast is present. [1](#0-0) 

2. `TopicMessageFilter.limit` is a `long` with `@Min(0)` but no `@Max`. `hasLimit()` is `limit > 0`. [2](#0-1) 

3. `TopicMessageRepositoryCustomImpl.findByFilter()` skips `setMaxResults` when `hasLimit()` is false and calls `getResultList()` unconditionally. [3](#0-2) 

4. `TopicMessageServiceImpl.subscribeTopic()` applies `flux.take(filter.getLimit())` at the Reactor level, but this is downstream of `getResultList()`, which has already materialized all rows into heap. [4](#0-3) 

All core technical claims check out. The overflow is real, the bypass is real, and the unbounded `getResultList()` call is real.

---

# Audit Report

## Title
Integer Overflow in `PollingTopicMessageRetriever.poll()` Bypasses `setMaxResults`, Enabling Unbounded In-Memory Load via `getResultList()`

## Summary
An unchecked `long→int` narrowing cast in `PollingTopicMessageRetriever.poll()` causes integer overflow when a user-supplied `limit` exceeds `Integer.MAX_VALUE`. The overflowed negative value propagates into a rebuilt `TopicMessageFilter` where `hasLimit()` evaluates to `false`, causing `TopicMessageRepositoryCustomImpl.findByFilter()` to skip `setMaxResults` entirely and call `getResultList()` with no row cap, materializing the entire topic message history into JVM heap.

## Finding Description

**File:** `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, lines 68–75

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())  // unchecked long→int cast
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());       // negative wins Math.min
var newFilter = filter.toBuilder().limit(pageSize)...build();   // limit = -2147483648
``` [5](#0-4) 

**File:** `grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java`, lines 51–60

```java
if (filter.hasLimit()) {            // (-2147483648 > 0) == false → SKIPPED
    typedQuery.setMaxResults(...);
}
return typedQuery.getResultList().stream(); // all rows loaded into heap
``` [3](#0-2) 

**Root cause:** `TopicMessageFilter.limit` is a `long` with `@Min(0)` but no upper bound constraint. [6](#0-5)  The cast `(int)(filter.getLimit() - context.getTotal().get())` silently overflows for any `limit > Integer.MAX_VALUE`. The result is a negative `pageSize` passed to `newFilter.limit(pageSize)`. Since `hasLimit()` is defined as `limit > 0`, a negative limit is treated as "no limit." [7](#0-6) 

**Failed assumption:** The design assumes `pageSize` is always a positive value bounded by `maxPageSize`. The unchecked narrowing cast breaks this invariant for any `limit > Integer.MAX_VALUE`.

**Note on the downstream `flux.take()` mitigation:** `TopicMessageServiceImpl.subscribeTopic()` applies `flux.take(filter.getLimit())` at the Reactor level. [4](#0-3)  However, this does **not** prevent the heap exhaustion: `getResultList()` fully materializes the JDBC result set into a `List<TopicMessage>` in memory *before* returning the `Stream`, so the damage occurs before Reactor can apply any limit.

## Impact Explanation
`getResultList()` materializes the full JDBC result set into a `List<TopicMessage>` in JVM heap before returning the `Stream`. With no `setMaxResults` guard, a topic with millions of messages causes a single poll to allocate all of them simultaneously. Multiple concurrent subscriptions with this payload can exhaust heap and crash the gRPC service (`OutOfMemoryError`), causing denial-of-service for all subscribers.

## Likelihood Explanation
Any unauthenticated gRPC client can call `subscribeTopic` with an arbitrary `limit` field (proto `uint64`). Setting `limit = 2147483648` (`Integer.MAX_VALUE + 1`) is sufficient to trigger the overflow. No special privileges, credentials, or knowledge of internal state are required. The attack is trivially repeatable and can be parallelized across many connections.

## Recommendation

1. **Eliminate the unchecked cast.** Replace the narrowing cast with a safe clamp:
   ```java
   long rawLimit = filter.getLimit() - context.getTotal().get();
   int limit = (int) Math.min(rawLimit, Integer.MAX_VALUE);
   ```
2. **Add an upper-bound constraint** on `TopicMessageFilter.limit`:
   ```java
   @Max(Integer.MAX_VALUE)
   @Min(0)
   private long limit;
   ```
3. **Validate at the gRPC boundary** in `ConsensusController` before constructing `TopicMessageFilter`, rejecting any `limit > Integer.MAX_VALUE` with an appropriate gRPC status error.
4. **Consider replacing `getResultList()` with `getResultStream()`** (with a proper cursor/fetch-size hint) to avoid full in-memory materialization, noting the existing comment about reactive stream compatibility.

## Proof of Concept

```
# gRPC call with limit = Integer.MAX_VALUE + 1 = 2147483648
grpcurl -d '{
  "topicID": {"topicNum": 1},
  "limit": 2147483648
}' <mirror-node-host>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

**Trace:**
1. `filter.getLimit()` = `2147483648L`, `context.getTotal().get()` = `0L`
2. `(int)(2147483648L - 0L)` = `(int)2147483648L` = `-2147483648` (overflow)
3. `Math.min(-2147483648, maxPageSize)` = `-2147483648`
4. `newFilter.limit(-2147483648)` → `hasLimit()` = `false`
5. `findByFilter()`: `setMaxResults` skipped → `getResultList()` returns all rows
6. All `TopicMessage` rows for the topic are allocated in heap simultaneously → OOM if topic is large

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/domain/TopicMessageFilter.java (L25-41)
```java
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
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-60)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }

        if (filter.getLimit() != 1) {
            // only apply the hint when limit is not 1
            entityManager.createNativeQuery(TOPIC_MESSAGES_BY_ID_QUERY_HINT).executeUpdate();
        }

        return typedQuery.getResultList().stream(); // getResultStream()'s cursor doesn't work with reactive streams
```

**File:** grpc/src/main/java/org/hiero/mirror/grpc/service/TopicMessageServiceImpl.java (L83-85)
```java
        if (filter.hasLimit()) {
            flux = flux.take(filter.getLimit());
        }
```
