All technical claims were verified against the actual source code. Here is the result:

---

Audit Report

## Title
Integer Overflow in `PollingTopicMessageRetriever.poll()` Bypasses `maxPageSize` Cap, Enabling Unbounded Database Queries

## Summary
A narrowing cast from `long` to `int` in `poll()` allows any caller supplying `limit = Long.MAX_VALUE` to produce `pageSize = -1`, which bypasses the `maxPageSize` guard and causes `findByFilter()` to issue SQL queries with no `LIMIT` clause against the `topic_message` table.

## Finding Description

**Exact location:** `grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java`, `poll()`, lines 68–71.

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())   // narrowing cast
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());        // guard bypassed
``` [1](#0-0) 

`filter.getLimit()` is declared as `long` and `context.getTotal().get()` returns `long`. Their difference is a `long`, then silently truncated to `int`. With `filter.getLimit() = Long.MAX_VALUE` and `total = 0`:

```
(int)(Long.MAX_VALUE - 0) == (int)(0x7FFFFFFFFFFFFFFF) == -1
Math.min(-1, 1000) == -1
``` [2](#0-1) 

**Why existing checks fail:**

1. `@Min(0)` on `TopicMessageFilter.limit` only rejects negative values. `Long.MAX_VALUE` is positive and passes validation at the `subscribeTopic` entry point. [2](#0-1) 

2. At line 75, the internal filter is rebuilt via `filter.toBuilder().limit(pageSize).startTime(startTime).build()` with `pageSize = -1`. This is a direct builder call — Spring AOP's `@Validated` interceptor is never invoked on it. [3](#0-2) 

3. `hasLimit()` returns `limit > 0`. With `limit = -1`, it returns `false`. [4](#0-3) 

4. In `TopicMessageRepositoryCustomImpl.findByFilter()`, `setMaxResults()` is only called when `filter.hasLimit()` is true. With `hasLimit() = false`, no `LIMIT` clause is applied to the SQL query. [5](#0-4) 

5. `isComplete()` checks `filter.getLimit() == total.get()`, i.e., `Long.MAX_VALUE == total`. This is never true in practice, so polling continues indefinitely (throttled: until `pageSize < maxPageSize`; unthrottled: until `numRepeats` exhausted). Since each unbounded query can return more rows than `maxPageSize`, `pageSize.get() >= maxPageSize` keeps `isComplete()` returning `false`, sustaining the loop. [6](#0-5) 

## Impact Explanation
Each invocation of `poll()` issues a SQL query with no `LIMIT` clause against the `topic_message` table, potentially causing a full table scan. In throttled mode (default polling interval: every 2 s), this repeats for the duration of the stream timeout (60 s by default), issuing ~30 unbounded queries per subscription. In unthrottled mode (polling interval: 20 ms), the rate is even higher. Multiple concurrent subscriptions amplify database load linearly. This constitutes a denial-of-service against the database tier.

## Likelihood Explanation
The gRPC `ConsensusService.subscribeTopic` RPC maps the protobuf `limit` field (a `uint64`) directly into `TopicMessageFilter.limit` (a Java `long`). No authentication or authorization is required to subscribe to a topic. Any network-reachable client can send a `ConsensusTopicQuery` with `limit = 0xFFFFFFFFFFFFFFFF` (`Long.MAX_VALUE` when interpreted as a signed Java `long`). The attack requires zero privileges and is trivially scriptable and repeatable.

## Recommendation
Replace the unchecked narrowing cast with a bounds-safe computation:

```java
long remaining = filter.hasLimit()
        ? filter.getLimit() - context.getTotal().get()
        : Integer.MAX_VALUE;
int limit = (int) Math.min(remaining, Integer.MAX_VALUE);
int pageSize = Math.min(limit, context.getMaxPageSize());
```

Additionally, add an upper-bound constraint on `TopicMessageFilter.limit` (e.g., `@Max(Integer.MAX_VALUE)`) to prevent values that would overflow when cast to `int` from ever entering the system.

## Proof of Concept

```java
// Attacker sends a ConsensusTopicQuery with limit = Long.MAX_VALUE
// In poll():
long filterLimit = Long.MAX_VALUE;  // from attacker-controlled input
long total = 0L;                    // no messages received yet
int limit = (int)(filterLimit - total);  // (int)(0x7FFFFFFFFFFFFFFF) == -1
int pageSize = Math.min(-1, 1000);       // == -1

// Internal filter built with limit = -1
// hasLimit() returns false (-1 > 0 is false)
// findByFilter() calls setMaxResults() only if hasLimit() is true → skipped
// SQL query issued with no LIMIT clause → full table scan
// isComplete() checks Long.MAX_VALUE == total → always false → polling repeats
```

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/repository/TopicMessageRepositoryCustomImpl.java (L51-53)
```java
        if (filter.hasLimit()) {
            typedQuery.setMaxResults((int) filter.getLimit());
        }
```
