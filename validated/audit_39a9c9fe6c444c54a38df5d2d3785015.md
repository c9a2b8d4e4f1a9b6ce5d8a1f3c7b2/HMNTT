After carefully reading all referenced files, the technical chain described in the claim is accurate and verifiable in the actual code.

---

Audit Report

## Title
Integer Overflow in `PollingTopicMessageRetriever.poll()` Causes Unbounded JPA Query via Crafted gRPC `limit`

## Summary
In `PollingTopicMessageRetriever.poll()`, a narrowing cast `(int)(filter.getLimit() - context.getTotal().get())` overflows when a user supplies `limit = 2147483648L` (Integer.MAX_VALUE + 1) via the gRPC `uint64 limit` field. The resulting `-2147483648` is stored as the `limit` of an internally-built `TopicMessageFilter`. Because `hasLimit()` checks `limit > 0`, the negative value causes `setMaxResults()` to be skipped in `TopicMessageRepositoryCustomImpl.findByFilter()`, producing an unbounded full-table scan on every poll iteration. The polling loop never terminates on the limit condition, repeating until the retriever timeout.

## Finding Description

**Entry point — `ConsensusController.toFilter()`:**

The `limit` field from the gRPC proto is passed directly to the filter builder with no upper-bound check: [1](#0-0) 

The only constraint on `TopicMessageFilter.limit` is `@Min(0)`: [2](#0-1) 

`2147483648L >= 0`, so it passes validation. `hasLimit()` returns `true` since `2147483648L > 0`: [3](#0-2) 

**Overflow site — `PollingTopicMessageRetriever.poll()`, lines 68–71:**

```
filter.getLimit() = 2147483648L, context.getTotal().get() = 0
(int)(2147483648L - 0L) = (int)(2147483648L) = -2147483648  // Integer.MIN_VALUE
Math.min(-2147483648, maxPageSize)             = -2147483648  // maxPageSize is positive
``` [4](#0-3) 

The poisoned value is written into a new filter that is never re-validated: [5](#0-4) 

**Sink — `TopicMessageRepositoryCustomImpl.findByFilter()`:**

`hasLimit()` is `limit > 0`. With `limit = -2147483648`, the check is `false`, so `setMaxResults()` is never called — the JPA query runs with no row limit: [6](#0-5) 

**Loop persistence — `PollingContext.isComplete()`:**

`isComplete()` uses the *original* filter's `limit = 2147483648L`. `limitHit` requires `total.get() == 2147483648L`, which is never reached. For the throttled path, the loop also continues as long as the unbounded query returns `>= maxPageSize` rows: [7](#0-6) 

The throttled retriever runs with `numRepeats = Long.MAX_VALUE` and repeats until the configured `timeout` (default 60 s): [8](#0-7) [9](#0-8) 

## Impact Explanation
Each poll cycle issues a JPA query with no `LIMIT` clause against the `topic_message` table for the targeted topic and start time. On a high-volume topic this loads the entire result set into JVM heap. Multiple concurrent connections with this payload simultaneously exhaust database I/O, connection pool slots, and JVM heap. The mirror node's gRPC `subscribeTopic` service becomes unavailable to legitimate subscribers. The 60-second timeout provides a partial bound per connection, but the attack is trivially repeatable and scriptable.

## Likelihood Explanation
The `subscribeTopic` gRPC endpoint is unauthenticated and publicly accessible. The proto `uint64 limit` field accepts any 64-bit value. Supplying `2147483648` requires no special knowledge beyond the published proto schema. The attack is a single protobuf message, requires no credentials, and can be scripted to maintain continuous pressure.

## Recommendation
1. **Clamp the cast**: Replace the unchecked narrowing cast with a safe clamp before converting to `int`:
   ```java
   long remaining = filter.getLimit() - context.getTotal().get();
   int limit = (int) Math.min(remaining, Integer.MAX_VALUE);
   ```
2. **Add an upper-bound constraint**: Add `@Max(Integer.MAX_VALUE)` (or a domain-appropriate maximum) to `TopicMessageFilter.limit` so values that would overflow `int` are rejected at the validation boundary.
3. **Validate at the service boundary**: Annotate the `filter` parameter of `TopicMessageServiceImpl.subscribeTopic()` with `@Valid` so Spring's method-level validation actually fires for incoming filters.

## Proof of Concept
```
# gRPC call with limit = 2^31 = 2147483648
grpcurl -plaintext -d '{
  "topicID": {"topicNum": <high-volume-topic>},
  "consensusStartTime": {"seconds": 0},
  "limit": 2147483648
}' <mirror-node>:5600 com.hedera.mirror.api.proto.ConsensusService/subscribeTopic
```

Execution trace:
1. `ConsensusController.toFilter()` sets `filter.limit = 2147483648L` — passes `@Min(0)`.
2. `PollingTopicMessageRetriever.poll()`: `(int)(2147483648L) = -2147483648`; `pageSize = -2147483648`.
3. `newFilter.limit = -2147483648L`; `newFilter.hasLimit()` → `false`.
4. `findByFilter()` skips `setMaxResults()` → full table scan issued.
5. `isComplete()` never returns `true` on the limit condition; loop repeats every 2 s until the 60 s timeout, issuing ~30 unbounded queries per connection.

### Citations

**File:** grpc/src/main/java/org/hiero/mirror/grpc/controller/ConsensusController.java (L56-56)
```java
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/PollingTopicMessageRetriever.java (L98-101)
```java
            if (throttled) {
                numRepeats = Long.MAX_VALUE;
                frequency = retrieverProperties.getPollingFrequency();
                maxPageSize = retrieverProperties.getMaxPageSize();
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

**File:** grpc/src/main/java/org/hiero/mirror/grpc/retriever/RetrieverProperties.java (L22-28)
```java
    private int maxPageSize = 1000;

    @NotNull
    private Duration pollingFrequency = Duration.ofSeconds(2L);

    @NotNull
    private Duration timeout = Duration.ofSeconds(60L);
```
