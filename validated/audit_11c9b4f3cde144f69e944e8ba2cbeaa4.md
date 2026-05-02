All steps of the vulnerability chain are verified against the actual source code. Here is the audit report:

---

Audit Report

## Title
`long`-to-`int` Narrowing Cast in `PollingTopicListener.poll()` Bypasses `maxPageSize` and Returns Unlimited Topic Messages

## Summary
In `PollingTopicListener.poll()`, the expression `(int)(filter.getLimit() - context.getCount().get())` performs an unchecked narrowing cast from `long` to `int`. A user-supplied limit value greater than `Integer.MAX_VALUE` (e.g., `Long.MAX_VALUE`) produces `-1` after the cast. This negative value causes the internally-constructed `newFilter` to have `hasLimit() == false`, which causes `TopicMessageRepositoryCustomImpl.findByFilter()` to skip `setMaxResults()` entirely, returning all rows for the topic from the database with no page cap. The `maxPageSize` guard is also bypassed because `Math.min(-1, maxPageSize) = -1`.

## Finding Description

**Step 1 — No upper-bound check at the entry point.**

`ConsensusController.toFilter()` maps the protobuf `uint64` field directly to `TopicMessageFilter.limit` with no upper-bound check: [1](#0-0) 

The only constraint on `TopicMessageFilter.limit` is `@Min(0)`: [2](#0-1) 

`Long.MAX_VALUE` satisfies `@Min(0)`, so validation passes.

**Step 2 — Outer flux cap is ineffective.**

`TopicMessageServiceImpl.subscribeTopic()` calls `flux.take(filter.getLimit())` only when `hasLimit()` is true: [3](#0-2) 

With `limit = Long.MAX_VALUE`, `hasLimit()` returns `true` (since `Long.MAX_VALUE > 0`), so `flux.take(Long.MAX_VALUE)` is called — Reactor's "take everything", providing no real cap.

**Step 3 — Propagation to listener.**

`incomingMessages()` computes the remaining limit as `filter.getLimit() - topicContext.getCount().get()` (a `long`) and passes it into the filter given to `PollingTopicListener.listen()`: [4](#0-3) 

With `count = 0`, the `newFilter` passed to the listener has `limit = Long.MAX_VALUE`.

**Step 4 — Root cause: narrowing cast in `PollingTopicListener.poll()`.** [5](#0-4) 

```
(int)(Long.MAX_VALUE - 0L)
= (int)(0x7FFFFFFFFFFFFFFF)
= 0xFFFFFFFF  (lower 32 bits)
= -1          (signed int)
```

`limit = -1`. Then `Math.min(-1, maxPageSize) = -1` — the `maxPageSize` guard is bypassed because `-1` always wins `Math.min` against any positive value. The `newFilter` is built with `limit = -1`.

**Step 5 — `hasLimit()` returns `false` for negative values.** [6](#0-5) 

`-1 > 0` is `false`, so `hasLimit()` returns `false`.

**Step 6 — `setMaxResults` is never called.** [7](#0-6) 

With `hasLimit() == false`, `setMaxResults` is skipped. `getResultList()` then materializes the entire result set into heap memory: [8](#0-7) 

Note: the internal `newFilter` is constructed via the builder directly, not through Spring's `@Validated` proxy, so the `@Min(0)` constraint is never re-evaluated on the `-1` value.

## Impact Explanation

Every poll cycle (repeated at `listenerProperties.getInterval()` indefinitely via `RepeatSpec.times(Long.MAX_VALUE)`) issues an unbounded `SELECT` against the `topic_message` table for the targeted topic, loading all results into heap memory. This enables:

- **Data exfiltration**: all historical messages for any topic returned without limit
- **Database DoS**: repeated full-range scans at polling frequency (default 500ms)
- **OOM / heap exhaustion** on the mirror node: `getResultList()` materializes the entire result set [9](#0-8) 

## Likelihood Explanation

The gRPC `ConsensusService.subscribeTopic` endpoint is unauthenticated and publicly accessible. Any gRPC client can send a `ConsensusTopicQuery` with `limit = Long.MAX_VALUE` (or any value > `Integer.MAX_VALUE`, e.g., `2147483648`). No credentials, no special role, and no prior knowledge beyond the topic ID is required. The attack is trivially repeatable and scriptable. The `POLL` listener type must be active (configured via `hiero.mirror.grpc.listener.type = POLL`), but this is a supported and documented configuration. [10](#0-9) 

## Recommendation

Replace the narrowing cast with a safe clamp before casting to `int`. In `PollingTopicListener.poll()`:

```java
// Before (vulnerable):
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getCount().get())
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());

// After (safe):
long remaining = filter.hasLimit()
        ? filter.getLimit() - context.getCount().get()
        : Long.MAX_VALUE;
int pageSize = (int) Math.min(remaining, listenerProperties.getMaxPageSize());
```

By performing `Math.min` against `maxPageSize` (a positive `int`) while both operands are still `long`, the result is always in `[0, maxPageSize]` before the cast, eliminating the overflow. Additionally, consider adding an upper-bound validation (e.g., `@Max(Integer.MAX_VALUE)`) on `TopicMessageFilter.limit` in `ConsensusController.toFilter()` as a defense-in-depth measure.

## Proof of Concept

```java
// gRPC client pseudocode
ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
    .setTopicID(TopicID.newBuilder().setTopicNum(1).build())
    .setLimit(Long.MAX_VALUE)  // or any value > Integer.MAX_VALUE
    .build();

stub.subscribeTopic(query, responseObserver);
// Each poll cycle issues SELECT * FROM topic_message WHERE topic_id = 1
// with no LIMIT clause, returning all rows and loading them into heap.
```

The arithmetic:
```
filter.getLimit()           = 0x7FFFFFFFFFFFFFFF (Long.MAX_VALUE)
context.getCount().get()    = 0x0000000000000000
difference (long)           = 0x7FFFFFFFFFFFFFFF
(int) cast (lower 32 bits)  = 0xFFFFFFFF = -1
Math.min(-1, maxPageSize)   = -1
newFilter.hasLimit()        = (-1 > 0) = false
setMaxResults() called?     = NO → unbounded query
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L38-43)
```java
        return Flux.defer(() -> poll(context))
                .delaySubscription(interval, scheduler)
                .repeatWhen(RepeatSpec.times(Long.MAX_VALUE)
                        .jitter(0.1)
                        .withFixedDelay(interval)
                        .withScheduler(scheduler))
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/ListenerProperties.java (L25-26)
```java
    @Min(32)
    private int maxPageSize = 5000;
```
